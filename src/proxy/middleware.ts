/**
 * MCP Security Proxy — 核心中间件
 * 负责人：C
 *
 * 职责：
 *   - MCP-in-the-Middle 代理主入口，拦截 Agent ↔ MCP Server 间的双向流量
 *   - 串联 "检测 → 研判 → 决策 → 溯源" 完整安全管道
 *   - 管理各子模块的生命周期
 *
 * 数据流：
 *   Agent 请求 → parse MCP → RequestInterceptor → DetectionEngine(A) →
 *   AlignmentEngine(B) → DecisionEngine(B) → 决策(ALLOW/ASK_USER/BLOCK) →
 *   如 ALLOW → 转发至上游 MCP Server → ResponseInterceptor → 二次扫描 →
 *   Tracer(C)记录 → 返回 Agent
 */

import { JsonRpcRequest, JsonRpcResponse, McpTransport, MCP_METHODS, MCP_ERROR_CODES } from './mcp-transport';
import { RequestInterceptor, ToolCallContext } from './request-interceptor';
import { ResponseInterceptor, ToolResponseContext, PayloadScanResult } from './response-interceptor';
import { DetectionEngine, DetectionResult } from '../detector/detection-engine';
import { DecisionEngine, DecisionResult } from '../policy/decision-engine';
import { RuleEvaluator } from '../policy/rule-evaluator';
import { DslParser } from '../policy/dsl-parser';
import { DeviationScorer, DeviationReport } from '../aligner/deviation-scorer';
import { StructuredIntent, IntentExtractor } from '../aligner/intent-extractor';
import { StructuredPlan, PlanAnalyzer } from '../aligner/plan-analyzer';
import { Tracer, ToolCallRecord } from '../tracer/call-graph';
import { AuditLogger } from '../tracer/audit-logger';
import { UpstreamMCPClient } from './mcp-transport';

export interface ProxyConfig {
  /** 上游真实 MCP Server 地址 */
  upstreamMcpUrl: string;
  /** 策略规则目录 */
  policyConfigPath: string;
  /** 审计日志文件路径 */
  auditLogPath: string;
  /** 代理监听端口（HTTP 模式） */
  listenPort?: number;
  /** 代理监听主机 */
  listenHost?: string;
  /** 默认决策（未匹配策略时） */
  defaultAction: 'ALLOW' | 'ASK_USER' | 'BLOCK';
  /** 启用混合模式 */
  verbose?: boolean;
}

/**
 * 管道处理结果
 */
export interface PipelineResult {
  decision: DecisionResult;
  detection: DetectionResult | null;
  scanResult: PayloadScanResult | null;
  traceRecord: ToolCallRecord | null;
}

export class McpSecurityProxy {
  private requestInterceptor: RequestInterceptor;
  private responseInterceptor: ResponseInterceptor;
  private detectionEngine: DetectionEngine;
  private decisionEngine: DecisionEngine;
  private deviationScorer: DeviationScorer;
  private intentExtractor: IntentExtractor;
  private planAnalyzer: PlanAnalyzer;
  private tracer: Tracer;
  private auditLogger: AuditLogger;
  private upstreamClient: UpstreamMCPClient;
  private ruleEvaluator: RuleEvaluator;
  private dslParser: DslParser;
  private config: ProxyConfig;
  private running = false;

  constructor(config: ProxyConfig) {
    this.config = config;

    // 初始化拦截器
    this.requestInterceptor = new RequestInterceptor();
    this.responseInterceptor = new ResponseInterceptor();

    // 初始化安全模块
    this.detectionEngine = new DetectionEngine();
    this.decisionEngine = new DecisionEngine();
    this.deviationScorer = new DeviationScorer();
    this.intentExtractor = new IntentExtractor();
    this.planAnalyzer = new PlanAnalyzer();
    this.ruleEvaluator = new RuleEvaluator();
    this.dslParser = new DslParser();

    // 初始化追踪
    this.tracer = new Tracer(config.auditLogPath);
    this.auditLogger = new AuditLogger(config.auditLogPath);

    // 初始化上游客户端
    this.upstreamClient = new UpstreamMCPClient(config.upstreamMcpUrl);
  }

  /**
   * 处理 Agent → MCP 的工具调用请求
   *
   * 完整管道：
   *   1. 解析 MCP 请求 → ToolCallContext
   *   2. 注入检测 → DetectionResult
   *   3. 意图提取 + 计划分析 → StructuredIntent + StructuredPlan
   *   4. 偏离度评分 → DeviationReport
   *   5. 策略评估 + 综合决策 → DecisionResult
   *   6. 执行决策：ALLOW(转发) / ASK_USER(暂停) / BLOCK(拒绝)
   *   7. 审计记录
   *
   * @param rawRequest MCP JSON-RPC 请求
   * @param sessionId 会话 ID
   * @returns MCP JSON-RPC 响应
   */
  async handleToolCall(
    rawRequest: JsonRpcRequest,
    sessionId: string = 'default'
  ): Promise<JsonRpcResponse> {
    const startTime = Date.now();

    try {
      // ---- 步骤 1：解析请求 ----
      const context = this.requestInterceptor.intercept(rawRequest, sessionId);

      if (this.config.verbose) {
        console.error(`[Proxy] Intercepted tool call: ${context.toolName}`, context.toolArgs);
      }

      // ---- 步骤 2：注入检测 (子任务 A) ----
      const detection = await this.detectionEngine.analyze({
        source: 'user_input',
        content: JSON.stringify(context.toolArgs),
        metadata: {
          toolName: context.toolName,
          conversationHistory: context.conversationHistory,
        },
      });

      if (this.config.verbose && detection.isInjection) {
        console.error(
          `[Proxy] ⚠️ Injection detected: type=${detection.injectionType}, confidence=${detection.confidence}`
        );
      }

      // ---- 步骤 3：意图-计划语义对齐 (子任务 B) ----
      let intent: StructuredIntent = {
        taskType: 'unknown',
        targetScope: {},
        requiredPermissions: [],
        explicitDenials: [],
        expectedOutcome: '',
        confidence: 0,
      };
      let plan: StructuredPlan = {
        steps: [],
        totalTools: [],
        declaredGoal: '',
        suspiciousFlags: [],
      };

      try {
        const userMessages = context.conversationHistory.length > 0
          ? context.conversationHistory
          : [context.userOriginalIntent || `User requested tool: ${context.toolName}`];

        intent = await this.intentExtractor.extract(userMessages);
        plan = this.planAnalyzer.analyze(context.agentPlanSteps.join('\n') || context.toolName);
      } catch {
        // 意图/计划分析失败不影响主流程，使用默认值
      }

      // ---- 步骤 4：偏离度评分 ----
      let deviation: DeviationReport = {
        overallScore: 0,
        dimensionScores: {
          goalDeviation: 0,
          scopeDeviation: 0,
          toolDeviation: 0,
          dataFlowDeviation: 0,
        },
        explanationMarkdown: '无法计算偏离度（意图分析未完成）',
        keyEvidence: [],
      };

      try {
        const toolCalls: ToolCallRecord[] = [{
          id: `call_${Date.now()}`,
          timestamp: context.timestamp,
          agentId: sessionId,
          toolName: context.toolName,
          toolArgs: context.toolArgs,
          isSuspicious: detection.isInjection,
          suspicionReason: detection.isInjection ? detection.injectionType : undefined,
          sourceAttribution: {
            type: 'user_input',
            sourceId: String(rawRequest.id),
            sourceSnippet: JSON.stringify(context.toolArgs).slice(0, 200),
          },
        }];

        deviation = this.deviationScorer.score(intent, plan, toolCalls);
      } catch {
        // 偏离度评分失败使用默认零值（不偏离）
      }

      // ---- 步骤 5：策略评估 + 综合决策 ----
      const policyEval = this.ruleEvaluator.evaluate(context, detection);

      const decision = this.decisionEngine.evaluate(
        detection,
        deviation,
        policyEval
      );

      if (this.config.verbose) {
        console.error(
          `[Proxy] Decision: ${decision.action} | risk=${decision.riskScore} | deviation=${decision.deviationScore}`
        );
      }

      // ---- 步骤 6：执行决策 ----
      let response: JsonRpcResponse;

      switch (decision.action) {
        case 'BLOCK': {
          // 强制阻断，返回安全错误
          response = McpTransport.createErrorResponse(
            rawRequest.id,
            MCP_ERROR_CODES.SECURITY_BLOCKED,
            decision.explanation,
            {
              riskScore: decision.riskScore,
              deviationScore: decision.deviationScore,
              matchedPolicy: decision.matchedPolicyId,
            }
          );
          break;
        }

        case 'ASK_USER': {
          // 在自动化场景中，ASK_USER 降级为 BLOCK（安全优先）
          // 在交互式场景中，应暂停并等待用户确认
          response = McpTransport.createErrorResponse(
            rawRequest.id,
            MCP_ERROR_CODES.SECURITY_SUSPICIOUS,
            `[需要确认] ${decision.explanation}`,
            {
              riskScore: decision.riskScore,
              deviationScore: decision.deviationScore,
              requiresUserConfirmation: true,
              userPrompt: this.decisionEngine.generateUserPrompt(decision),
            }
          );
          break;
        }

        case 'ALLOW':
        default: {
          // 放行 — 转发到上游 MCP Server
          try {
            // 转发前修改请求（如需要的话——例如清理敏感参数）
            response = await this.upstreamClient.forward(rawRequest);

            // 对上游返回的内容进行间接注入扫描
            const toolArgs = context.toolArgs;
            const scanContext = this.responseInterceptor.intercept(
              response,
              context.toolName,
              toolArgs
            );
            const scanResult = this.responseInterceptor.scanForPayload(scanContext);

            if (scanResult.suspicious) {
              // 在响应中标记可疑内容（不阻断，但警告）
              if (this.config.verbose) {
                console.error(
                  `[Proxy] ⚠️ Suspicious payload in response: ${scanResult.attackType}`
                );
              }
            }

            // 记录溯源
            await this.recordTrace(context, detection, decision, startTime, scanResult);
          } catch (forwardErr) {
            response = McpTransport.createErrorResponse(
              rawRequest.id,
              MCP_ERROR_CODES.INTERNAL_ERROR,
              `Failed to forward request: ${String(forwardErr)}`
            );
          }
          break;
        }
      }

      // ---- 步骤 7：审计记录 ----
      await this.auditLogger.log({
        level: 'DECISION',
        sessionId,
        agentId: sessionId,
        data: {
          toolName: context.toolName,
          toolArgs: context.toolArgs,
          decision: decision.action,
          riskScore: decision.riskScore,
          deviationScore: decision.deviationScore,
          injectionType: detection.injectionType,
          injectionConfidence: detection.confidence,
          latency: Date.now() - startTime,
        },
      });

      return response;

    } catch (err) {
      // 内部错误不崩溃，返回错误响应
      console.error(`[Proxy] Internal error handling tool call:`, err);
      return McpTransport.createErrorResponse(
        rawRequest.id ?? 0,
        MCP_ERROR_CODES.INTERNAL_ERROR,
        `Security proxy internal error: ${String(err)}`
      );
    }
  }

  /**
   * 处理 MCP → Agent 的工具返回结果（独立的间接注入扫描通道）
   */
  async handleToolResponse(
    rawResponse: JsonRpcResponse,
    toolName: string,
    toolArgs: Record<string, unknown>
  ): Promise<{ response: JsonRpcResponse; scanResult: PayloadScanResult | null }> {
    const context = this.responseInterceptor.intercept(rawResponse, toolName, toolArgs);
    const scanResult = this.responseInterceptor.scanForPayload(context);

    if (scanResult.suspicious && this.config.verbose) {
      console.error(
        `[Proxy] ⚠️ Suspicious content in tool response: type=${scanResult.attackType}, confidence=${scanResult.confidence}`
      );
    }

    return { response: rawResponse, scanResult };
  }

  /**
   * 记录溯源信息
   */
  private async recordTrace(
    context: ToolCallContext,
    detection: DetectionResult,
    decision: DecisionResult,
    startTime: number,
    scanResult: PayloadScanResult | null
  ): Promise<void> {
    const traceRecord: ToolCallRecord = {
      id: `trace_${Date.now()}_${Math.random().toString(36).slice(2, 7)}`,
      timestamp: context.timestamp,
      agentId: 'main-agent',
      toolName: context.toolName,
      toolArgs: context.toolArgs,
      isSuspicious: detection.isInjection || (scanResult?.suspicious ?? false),
      suspicionReason: detection.isInjection
        ? `Injection detected: ${detection.injectionType} (confidence: ${detection.confidence})`
        : scanResult?.suspicious
          ? `Suspicious response payload: ${scanResult?.attackType}`
          : undefined,
      sourceAttribution: {
        type: 'user_input',
        sourceId: context.toolName,
        sourceSnippet: JSON.stringify(context.toolArgs).slice(0, 500),
      },
    };

    this.tracer.record(traceRecord);

    // 审计日志
    await this.auditLogger.log({
      level: 'TRACE',
      sessionId: 'default',
      agentId: 'main-agent',
      data: {
        ...traceRecord,
        decision: decision.action,
        riskScore: decision.riskScore,
        latency: Date.now() - startTime,
      },
    });
  }

  /**
   * 更新会话上下文（Agent 收到用户新消息时调用）
   */
  updateSession(sessionId: string, userMessage: string): void {
    this.requestInterceptor.updateSession(sessionId, { conversationTurn: userMessage });
  }

  /**
   * 更新 Agent 计划（Agent 输出规划文本时调用）
   */
  updateAgentPlan(sessionId: string, planSteps: string[]): void {
    this.requestInterceptor.updateSession(sessionId, { planSteps });
  }

  /** 启动代理 */
  async start(): Promise<void> {
    this.running = true;

    // 加载策略规则
    try {
      const policies = await this.dslParser.parseDirectory(this.config.policyConfigPath);
      this.ruleEvaluator.loadPolicies(policies);
      console.error(`[Proxy] Loaded ${policies.metadata.totalRules} policy rules from ${policies.metadata.sourceFiles.length} files`);
    } catch (e) {
      console.error(`[Proxy] ⚠️ Failed to load policies: ${e}. Using empty rule set.`);
    }

    // 检查上游 MCP 连接
    const upstreamOk = await this.upstreamClient.healthCheck();
    if (!upstreamOk) {
      console.error('[Proxy] ⚠️ Warning: Upstream MCP server is not reachable. ' +
        `Make sure ${this.config.upstreamMcpUrl} is running.`);
    } else {
      console.error(`[Proxy] ✓ Connected to upstream MCP server at ${this.config.upstreamMcpUrl}`);
    }

    console.error(`[Proxy] Security proxy started. Default action: ${this.config.defaultAction}`);
  }

  /** 停止代理 */
  async stop(): Promise<void> {
    this.running = false;
    console.error('[Proxy] Security proxy stopped.');
  }

  /** 是否为运行状态 */
  get isRunning(): boolean {
    return this.running;
  }
}
