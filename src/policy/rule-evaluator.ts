/**
 * 规则评估器
 * 负责人：B
 *
 * 职责：
 *   - 在运行时将工具调用请求与策略规则集进行匹配
 *   - 执行规则表达式评估
 *   - 返回最高优先级策略决策
 *
 * 匹配流程：
 *   1. 按 tool 过滤候选规则（精确匹配 + 通配符匹配）
 *   2. 按 risk 降序评估每条规则
 *   3. 返回第一个完全匹配的规则
 */

import { PolicyRule, ParsedPolicySet } from './dsl-parser';
import { ExpressionEvaluator, MatchContext } from './expression-evaluator';
import { ToolCallContext } from '../proxy/request-interceptor';
import { DetectionResult } from '../detector/detection-engine';

export interface EvaluationResult {
  matched: boolean;
  matchedRule?: PolicyRule;
  action: 'ALLOW' | 'ASK_USER' | 'BLOCK';
  riskScore: number;
  message?: string;
  matchedCondition?: string;
}

export class RuleEvaluator {
  private policies: ParsedPolicySet | null = null;
  private expressionEvaluator: ExpressionEvaluator;

  constructor() {
    this.expressionEvaluator = new ExpressionEvaluator();
  }

  /**
   * 加载策略集
   */
  loadPolicies(policies: ParsedPolicySet): void {
    this.policies = policies;
  }

  /**
   * 评估工具调用是否命中策略规则
   *
   * @param context 工具调用上下文
   * @param detection 注入检测结果
   * @returns 评估结果（包含决策动作）
   */
  evaluate(context: ToolCallContext, detection: DetectionResult): EvaluationResult {
    if (!this.policies || this.policies.rules.length === 0) {
      return {
        matched: false,
        action: 'ALLOW',
        riskScore: Math.round(detection.confidence * 100),
      };
    }

    // 步骤 1：按 tool 过滤候选规则
    const candidates = this.filterByTool(context.toolName);

    if (candidates.length === 0) {
      return {
        matched: false,
        action: 'ALLOW',
        riskScore: Math.round(detection.confidence * 100),
      };
    }

    // 步骤 2：构建匹配上下文
    const matchContext = this.buildMatchContext(context, detection);

    // 步骤 3：按优先级逐条评估（已排序，先评估最高风险）
    for (const rule of candidates) {
      if (!rule.enabled) continue;

      const matched = this.expressionEvaluator.evaluate(rule.rule, matchContext);

      if (matched) {
        const riskScore = this.calculateRiskScore(detection, 0, rule);

        return {
          matched: true,
          matchedRule: rule,
          action: rule.action,
          riskScore,
          message: rule.message,
          matchedCondition: rule.rule,
        };
      }
    }

    // 步骤 4：无匹配，默认放行
    return {
      matched: false,
      action: 'ALLOW',
      riskScore: this.calculateRiskScore(detection, 0),
    };
  }

  /**
   * 按工具名过滤候选规则（支持通配符）
   * fs.* 匹配 fs.write, fs.read, fs.delete 等
   */
  private filterByTool(toolName: string): PolicyRule[] {
    if (!this.policies) return [];

    return this.policies.rules.filter(rule => {
      const ruleTool = rule.tool;

      // 精确匹配
      if (ruleTool === toolName) return true;

      // 通配符匹配：fs.* 匹配 fs.write, fs.read 等
      if (ruleTool.endsWith('.*')) {
        const prefix = ruleTool.slice(0, -2);
        return toolName.startsWith(prefix + '.');
      }

      // 前缀匹配：exec 匹配 exec, exec.command 等
      if (!ruleTool.includes('.') && !ruleTool.includes('*')) {
        return toolName === ruleTool || toolName.startsWith(ruleTool + '.');
      }

      return false;
    });
  }

  /**
   * 构建匹配上下文
   * 将 ToolCallContext + DetectionResult 转换为 ExpressionEvaluator 所需的 MatchContext
   */
  private buildMatchContext(context: ToolCallContext, detection: DetectionResult): MatchContext {
    const toolArgs = context.toolArgs;

    const matchCtx: MatchContext = {
      user_original_intent: context.userOriginalIntent,
      command: typeof toolArgs.command === 'string' ? toolArgs.command : undefined,
      target_path: typeof toolArgs.path === 'string' ? toolArgs.path :
                   typeof toolArgs.target_path === 'string' ? toolArgs.target_path :
                   typeof toolArgs.filePath === 'string' ? toolArgs.filePath : undefined,
      target_url: typeof toolArgs.url === 'string' ? toolArgs.url :
                  typeof toolArgs.target_url === 'string' ? toolArgs.target_url : undefined,
      target_remote: typeof toolArgs.remote === 'string' ? toolArgs.remote : undefined,
    };

    // 敏感数据检测（如果检测到注入，标记为敏感）
    if (detection.isInjection) {
      matchCtx.session_sensitive_data = [detection.payloadSnippet];
      matchCtx.read_file_content = detection.payloadSnippet;
    }

    // exec 相关
    if (typeof toolArgs.command === 'string') {
      matchCtx.command = toolArgs.command;
    }

    // net.fetch 相关
    if (typeof toolArgs.body === 'string') {
      matchCtx.request_body = toolArgs.body;
      matchCtx.request_body_size = toolArgs.body.length;
    } else if (typeof toolArgs.data === 'string') {
      matchCtx.request_body = toolArgs.data;
      matchCtx.request_body_size = toolArgs.data.length;
    }

    // git 相关
    if (toolArgs.staged_files) {
      matchCtx.staged_files = Array.isArray(toolArgs.staged_files)
        ? toolArgs.staged_files.map(String)
        : [String(toolArgs.staged_files)];
    }

    // agent 相关
    if (typeof toolArgs.context === 'string') {
      matchCtx.subagent_context = toolArgs.context;
    }
    if (typeof toolArgs.message === 'string') {
      matchCtx.message_content = toolArgs.message;
    }
    if (typeof toolArgs.permissions === 'object') {
      matchCtx.subagent_permissions = this.extractStringArray(toolArgs.permissions);
    }
    if (typeof toolArgs.task === 'string') {
      matchCtx.subagent_task = toolArgs.task;
    }

    // args 中可能包含 -f 或 --force
    if (typeof toolArgs.args === 'string') {
      matchCtx.command_args = toolArgs.args;
    } else if (Array.isArray(toolArgs.args)) {
      matchCtx.command_args = toolArgs.args.join(' ');
    }

    return matchCtx;
  }

  /**
   * 计算综合风险评分（0-100）
   */
  calculateRiskScore(
    detection: DetectionResult,
    deviationScore: number,
    matchedRule?: PolicyRule
  ): number {
    const riskWeight: Record<string, number> = { 'CRITICAL': 100, 'HIGH': 75, 'MEDIUM': 50, 'LOW': 25 };

    let score = 0;

    // 注入检测贡献 (40%)
    score += detection.confidence * 40;

    // 偏离度贡献 (40%)
    score += deviationScore * 40;

    // 策略风险贡献 (20%)
    if (matchedRule) {
      score += (riskWeight[matchedRule.risk] ?? 0) * 0.2;
    }

    return Math.round(Math.min(score, 100));
  }

  private extractStringArray(val: unknown): string[] {
    if (Array.isArray(val)) return val.map(String);
    if (typeof val === 'string') return [val];
    return [];
  }
}
