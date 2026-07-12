/**
 * 偏离度评分器
 * 负责人：B
 *
 * 计算"用户原始意图"与"Agent实际执行计划+工具调用序列"之间的语义偏离度。
 *
 * 评分维度（加权综合）：
 *   1. 目标偏离度 (30%)：Agent 执行目标是否与用户意图一致
 *   2. 范围偏离度 (25%)：操作的文件/网络/仓库是否超出用户声明的范围
 *   3. 工具偏离度 (25%)：实际使用的工具是否超出任务最小必要集
 *   4. 数据流偏离度 (20%)：是否存在向不可信目标的非必要数据传输
 */

import * as os from 'os';
import { StructuredIntent } from './intent-extractor';
import { StructuredPlan } from './plan-analyzer';
import { ToolCallRecord } from '../tracer/call-graph';

export interface DeviationReport {
  overallScore: number;
  dimensionScores: {
    goalDeviation: number;
    scopeDeviation: number;
    toolDeviation: number;
    dataFlowDeviation: number;
  };
  explanationMarkdown: string;
  keyEvidence: Array<{
    expected: string;
    actual: string;
    severity: 'low' | 'medium' | 'high' | 'critical';
  }>;
}

export class DeviationScorer {
  /**
   * 敏感路径模式（访问这些路径 → 高偏离度）
   */
  private static readonly SENSITIVE_PATHS = [
    '~/.ssh/', '/home/', '/root/', '/etc/passwd', '/etc/shadow',
    '~/.aws/', '.env', 'credentials', 'id_rsa', '*.pem', '*.key',
    '/etc/cron', '/etc/init.d/', '/etc/systemd/',
  ];

  /**
   * 数据外发工具（使用这些工具传输数据 → 数据流偏离）
   */
  private static readonly EXFILTRATION_TOOLS = [
    'net.fetch', 'net.request', 'net.websocket',
  ];

  /**
   * 计算意图-执行偏离度
   */
  score(
    intent: StructuredIntent,
    plan: StructuredPlan,
    toolCalls: ToolCallRecord[]
  ): DeviationReport {
    // 维度 1：目标偏离度 (30%)
    const goalDeviation = this.scoreGoalDeviation(intent, plan, toolCalls);

    // 维度 2：范围偏离度 (25%)
    const scopeDeviation = this.scoreScopeDeviation(intent, toolCalls);

    // 维度 3：工具偏离度 (25%)
    const toolDeviation = this.scoreToolDeviation(intent, toolCalls);

    // 维度 4：数据流偏离度 (20%)
    const dataFlowDeviation = this.scoreDataFlowDeviation(toolCalls);

    // 加权综合
    const overallScore =
      goalDeviation * 0.30 +
      scopeDeviation * 0.25 +
      toolDeviation * 0.25 +
      dataFlowDeviation * 0.20;

    // 收集关键证据
    const keyEvidence = this.collectEvidence(intent, toolCalls, {
      goalDeviation, scopeDeviation, toolDeviation, dataFlowDeviation,
    });

    return {
      overallScore: Math.round(overallScore * 100) / 100,
      dimensionScores: {
        goalDeviation: Math.round(goalDeviation * 100) / 100,
        scopeDeviation: Math.round(scopeDeviation * 100) / 100,
        toolDeviation: Math.round(toolDeviation * 100) / 100,
        dataFlowDeviation: Math.round(dataFlowDeviation * 100) / 100,
      },
      explanationMarkdown: this.generateExplanation(intent, toolCalls, {
        goalDeviation, scopeDeviation, toolDeviation, dataFlowDeviation,
      }),
      keyEvidence,
    };
  }

  /**
   * 目标偏离度评分
   * 意图类型 vs 实际工具调用是否匹配
   */
  private scoreGoalDeviation(
    intent: StructuredIntent,
    plan: StructuredPlan,
    toolCalls: ToolCallRecord[]
  ): number {
    let score = 0;

    // 规则 1：意图为 read/review，但出现了 write/push/exec
    if (['read', 'review', 'analyze', 'query'].includes(intent.taskType)) {
      const writeTools = toolCalls.filter(c =>
        c.toolName.startsWith('fs.write') ||
        c.toolName.startsWith('git.push') ||
        c.toolName.startsWith('exec') ||
        c.toolName.includes('delete')
      );
      if (writeTools.length > 0) {
        score += 0.4 + writeTools.length * 0.1;
      }
    }

    // 规则 2：意图为 review 但出现了 git.push
    if (intent.taskType === 'review') {
      const hasPush = toolCalls.some(c => c.toolName === 'git.push');
      if (hasPush) score += 0.5;
    }

    // 规则 3：计划中有可疑标记
    if (plan.suspiciousFlags.length > 0) {
      score += Math.min(plan.suspiciousFlags.length * 0.1, 0.3);
    }

    // 规则 4：意图为 deploy 之外却有 exec
    if (intent.taskType !== 'execute' && intent.taskType !== 'deploy') {
      const execCalls = toolCalls.filter(c => c.toolName.startsWith('exec'));
      if (execCalls.length > 0) score += 0.3 + execCalls.length * 0.1;
    }

    return Math.min(score, 1.0);
  }

  /**
   * 范围偏离度评分
   * 用户声明的操作范围 vs 实际访问的路径/URL
   */
  private scoreScopeDeviation(intent: StructuredIntent, toolCalls: ToolCallRecord[]): number {
    let score = 0;
    const intendedFiles = new Set(
      (intent.targetScope.files ?? []).map(f => f.toLowerCase())
    );

    for (const call of toolCalls) {
      // 提取实际访问的路径
      const path = this.extractPath(call);
      if (!path) continue;

      // 检查是否为敏感路径
      for (const sensitive of DeviationScorer.SENSITIVE_PATHS) {
        const normPath = path.toLowerCase().replace(/^~/, os.homedir());
        const normSensitive = sensitive.toLowerCase().replace(/^~/, os.homedir());

        if (normPath.includes(normSensitive) || this.globMatch(normPath, normSensitive)) {
          score += 0.3;
          break;
        }
      }

      // 检查是否超出用户声明的范围
      if (intendedFiles.size > 0) {
        const normPath = path.toLowerCase();
        const inScope = [...intendedFiles].some(f =>
          normPath.includes(f) || f.includes(normPath)
        );
        if (!inScope) score += 0.2;
      }
    }

    return Math.min(score, 1.0);
  }

  /**
   * 工具偏离度评分
   * 实际使用的工具 vs 任务最小必要权限
   */
  private scoreToolDeviation(intent: StructuredIntent, toolCalls: ToolCallRecord[]): number {
    let score = 0;
    const neededPermissions = new Set(intent.requiredPermissions);

    for (const call of toolCalls) {
      const toolFamily = call.toolName.split('.')[0];

      // 检查是否超出必要权限
      const exceedsPermission = ![...neededPermissions].some(perm =>
        perm === call.toolName || call.toolName.startsWith(perm)
      );

      if (exceedsPermission) {
        // 根据工具族加分
        switch (toolFamily) {
          case 'exec': score += 0.4; break;
          case 'git': score += 0.3; break;
          case 'net': score += 0.2; break;
          case 'agent': score += 0.25; break;
          default: score += 0.1;
        }
      }
    }

    return Math.min(score, 1.0);
  }

  /**
   * 数据流偏离度评分
   * 检查是否存在 读取敏感数据 → 外发 的数据流
   */
  private scoreDataFlowDeviation(toolCalls: ToolCallRecord[]): number {
    let score = 0;

    // 检查是否存在读→外发链
    const readCalls = toolCalls.filter(c => c.toolName.startsWith('fs.read'));
    const fetchCalls = toolCalls.filter(c =>
      DeviationScorer.EXFILTRATION_TOOLS.some(t => c.toolName.startsWith(t))
    );

    if (readCalls.length > 0 && fetchCalls.length > 0) {
      // 检查读取的内容是否通过 net.fetch 发出去
      const readPaths = readCalls.map(c => this.extractPath(c)).filter(Boolean);
      const fetchBodies = fetchCalls.map(c => {
        const body = c.toolArgs.body as string | undefined ??
                     c.toolArgs.data as string | undefined ??
                     '';
        return body;
      });

      // 如果外发请求体包含读取路径中的敏感关键词
      for (const path of readPaths) {
        for (const body of fetchBodies) {
          if (path && body && (body.includes(path) || this.containsSensitiveData(body))) {
            score += 0.5;
          }
        }
      }

      // 即使不完全匹配，读+外发的组合也加分
      score += 0.2;
    }

    // 检查是否向非信任域外发
    for (const call of fetchCalls) {
      const url = (call.toolArgs.url as string) ?? (call.toolArgs.target_url as string) ?? '';
      if (url && !this.isTrustedDomain(url)) {
        score += 0.3;
      }
    }

    return Math.min(score, 1.0);
  }

  /**
   * 收集偏离证据
   */
  private collectEvidence(
    intent: StructuredIntent,
    toolCalls: ToolCallRecord[],
    scores: { goalDeviation: number; scopeDeviation: number; toolDeviation: number; dataFlowDeviation: number }
  ): DeviationReport['keyEvidence'] {
    const evidence: DeviationReport['keyEvidence'] = [];

    if (scores.goalDeviation > 0.3) {
      evidence.push({
        expected: `任务类型为 "${intent.taskType}"，预期操作：${intent.requiredPermissions.join(', ')}`,
        actual: `实际调用：${toolCalls.map(c => c.toolName).join(', ')}`,
        severity: scores.goalDeviation > 0.6 ? 'critical' : scores.goalDeviation > 0.4 ? 'high' : 'medium',
      });
    }

    if (scores.scopeDeviation > 0.3) {
      const paths = toolCalls.map(c => this.extractPath(c)).filter(Boolean);
      evidence.push({
        expected: `操作范围：${(intent.targetScope.files ?? []).join(', ') || '未指定'}`,
        actual: `实际访问路径：${paths.join(', ')}`,
        severity: 'high',
      });
    }

    if (scores.dataFlowDeviation > 0.3) {
      evidence.push({
        expected: '数据应仅在本地处理',
        actual: '检测到数据外发操作',
        severity: 'critical',
      });
    }

    return evidence;
  }

  /**
   * 生成可解释研判结论
   */
  generateExplanation(
    intent: StructuredIntent,
    toolCalls: ToolCallRecord[],
    scores: { goalDeviation: number; scopeDeviation: number; toolDeviation: number; dataFlowDeviation: number }
  ): string {
    const overall = scores.goalDeviation * 0.30 + scores.scopeDeviation * 0.25 +
                    scores.toolDeviation * 0.25 + scores.dataFlowDeviation * 0.20;

    if (overall < 0.2) {
      return `用户原始请求为 ${intent.expectedOutcome}，Agent 的工具调用序列与意图一致，偏离度低（${(overall * 100).toFixed(0)}%）。`;
    }

    const parts: string[] = [`用户原始请求为 ${intent.expectedOutcome}`];

    // 列出偏离的工具调用
    const deviatingTools = toolCalls.filter(c => {
      const toolFamily = c.toolName.split('.')[0];
      return !intent.requiredPermissions.some(p => p.startsWith(toolFamily));
    });

    if (deviatingTools.length > 0) {
      parts.push(`Agent 却调用了 ${deviatingTools.map(c => `\`${c.toolName}\``).join('、')}`);
    }

    // 数据流偏离
    if (scores.dataFlowDeviation > 0.3) {
      const fetchCall = toolCalls.find(c =>
        DeviationScorer.EXFILTRATION_TOOLS.some(t => c.toolName.startsWith(t))
      );
      if (fetchCall) {
        const url = fetchCall.toolArgs.url ?? fetchCall.toolArgs.target_url ?? '未知目标';
        parts.push(`并通过 \`${fetchCall.toolName}\` 向 \`${url}\` 发起数据传输`);
      }
    }

    // 判定结论
    if (overall > 0.6) {
      parts.push(`偏离度评分 ${(overall * 100).toFixed(0)}%，判定为**严重偏离原始意图**，建议阻断。`);
    } else if (overall > 0.3) {
      parts.push(`偏离度评分 ${(overall * 100).toFixed(0)}%，存在**中等偏离**，建议用户确认。`);
    } else {
      parts.push(`偏离度评分 ${(overall * 100).toFixed(0)}%，轻微偏离。`);
    }

    return parts.join('，');
  }

  // ---- 辅助方法 ----

  private extractPath(call: ToolCallRecord): string {
    return (call.toolArgs.path as string) ??
           (call.toolArgs.target_path as string) ??
           (call.toolArgs.filePath as string) ??
           (call.toolArgs.file as string) ?? '';
  }

  private containsSensitiveData(text: string): boolean {
    return /-----BEGIN.*PRIVATE KEY-----/i.test(text) ||
           /sk-[a-zA-Z0-9]{20,}/.test(text) ||
           /ghp_[a-zA-Z0-9]{36}/.test(text) ||
           /AKIA[A-Z0-9]{16}/.test(text);
  }

  private isTrustedDomain(url: string): boolean {
    try {
      const hostname = new URL(url.startsWith('http') ? url : `https://${url}`).hostname;
      const trustedDomains = [
        'github.com', 'api.github.com', 'raw.githubusercontent.com',
        'registry.npmjs.org', 'pypi.org', 'files.pythonhosted.org',
        'localhost', '127.0.0.1',
      ];
      return trustedDomains.some(d => hostname === d || hostname.endsWith('.' + d));
    } catch {
      return false;
    }
  }

  private globMatch(str: string, pattern: string): boolean {
    const regexStr = pattern
      .replace(/[.+^${}()|[\]\\]/g, '\\$&')
      .replace(/\*\*/g, '<<<GLOBSTAR>>>')
      .replace(/\*/g, '[^/]*')
      .replace(/<<<GLOBSTAR>>>/g, '.*');
    try {
      return new RegExp(regexStr, 'i').test(str);
    } catch {
      return false;
    }
  }
}
