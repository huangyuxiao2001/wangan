/**
 * MCP 请求拦截器
 * 负责人：C
 *
 * 职责：
 *   - 截获所有 Agent → MCP Server 的工具调用请求
 *   - 解析 MCP JSON-RPC 协议消息，提取结构化的调用上下文
 *   - 传递给后续检测链
 *
 * 截获的方法：
 *   - tools/call     — 工具调用请求（核心拦截点）
 *   - tools/list     — 工具列表查询 → 扫描 tool description 是否含注入载荷
 *   - prompts/get    — Prompt 模板获取 → 扫描 prompt description
 *   - resources/read — 资源读取 → 标记间接注入来源
 */

import { JsonRpcRequest, McpTransport, MCP_METHODS } from './mcp-transport';

export interface ToolCallContext {
  /** 工具名（如 fs.read, net.fetch） */
  toolName: string;
  /** 工具调用参数 */
  toolArgs: Record<string, unknown>;
  /** MCP 方法（tools/call, 等） */
  mcpMethod: string;
  /** 请求消息 ID */
  requestId: string | number;
  /** 用户原始意图（由上游 Agent 通过 MCP 元数据传入，或从会话上下文注入） */
  userOriginalIntent: string;
  /** Agent 当前已声明的计划步骤（从 reasoning 输出中提取） */
  agentPlanSteps: string[];
  /** 会话上下文（用于跨轮检测） */
  conversationHistory: string[];
  /** 请求时间戳 */
  timestamp: number;
}

export class RequestInterceptor {
  /**
   * 会话上下文存储
   * Map<sessionId, SessionContext>
   */
  private sessions: Map<string, {
    userIntent: string;
    planSteps: string[];
    conversationHistory: string[];
  }> = new Map();

  /**
   * 拦截并解析 MCP JSON-RPC 工具调用请求
   *
   * MCP tools/call 协议格式：
   * {
   *   "jsonrpc": "2.0",
   *   "id": 1,
   *   "method": "tools/call",
   *   "params": {
   *     "name": "fs.read",          // 工具名
   *     "arguments": {               // 调用参数
   *       "path": "/some/file"
   *     }
   *   }
   * }
   *
   * @param rawRequest MCP JSON-RPC 原始请求对象
   * @param sessionId 会话标识（用于关联多轮对话上下文）
   * @returns 结构化的工具调用上下文
   */
  intercept(rawRequest: JsonRpcRequest, sessionId: string = 'default'): ToolCallContext {
    const method = rawRequest.method;
    let toolName = '';
    let toolArgs: Record<string, unknown> = {};

    // 提取工具名和参数
    if (method === MCP_METHODS.TOOLS_CALL) {
      const extracted = McpTransport.extractToolCall(rawRequest);
      if (extracted) {
        toolName = extracted.toolName;
        toolArgs = extracted.toolArgs;
      }
    }

    // 从会话中获取上下文
    const session = this.getOrCreateSession(sessionId);

    // 如果 Agent 通过 params._meta 传递了上下文，提取它
    const meta = rawRequest.params?.['_meta'] as Record<string, unknown> | undefined;
    if (meta) {
      if (typeof meta.userIntent === 'string') {
        session.userIntent = meta.userIntent;
      }
      if (Array.isArray(meta.planSteps)) {
        session.planSteps = meta.planSteps.map(String);
      }
    }

    return {
      toolName,
      toolArgs,
      mcpMethod: method,
      requestId: rawRequest.id,
      userOriginalIntent: session.userIntent,
      agentPlanSteps: session.planSteps,
      conversationHistory: session.conversationHistory,
      timestamp: Date.now(),
    };
  }

  /**
   * 扫描工具描述中是否包含注入载荷
   *
   * 攻击场景：恶意 MCP Server 在注册工具的 description 字段中嵌入隐藏指令，
   * 当 Agent 读取 tools/list 的返回结果时被激活。这是 MCP 供应链攻击的典型手法。
   *
   * @param description 工具的 description 文本
   * @returns 检测结果
   */
  scanToolDescription(description: string): {
    suspicious: boolean;
    patterns: string[];
  } {
    const patterns: string[] = [];

    // 检测指令性语言（工具描述不应包含指令）
    const instructionPatterns = [
      /ignore\s+(all\s+)?(previous|above|prior)\s+(instructions?|rules?|constraints?)/i,
      /you\s+(are|should|must|need\s+to)\s+(now\s+)?/i,
      /forget\s+(everything|all|the\s+above)/i,
      /disregard\s+(all\s+)?(previous|safety|security)/i,
      /你的新任务是/i,
      /忽略(所有|之前|上面|上文)/i,
      /你现在是/i,
      /扮演.*角色/i,
      /system\s*(prompt|message|instruction).*override/i,
      /override\s*(system|security|safety)/i,
      /execute\s+(this|the\s+following)\s+(command|code|script)/i,
      /请.*执行.*命令/i,
    ];

    for (const pattern of instructionPatterns) {
      if (pattern.test(description)) {
        patterns.push(`Instruction injection: matched "${pattern.source.slice(0, 40)}..." in tool description`);
      }
    }

    // 检测 URL/域名（可能是回连地址）
    const urlPatterns = [
      /https?:\/\/\S+/gi,
      /[a-zA-Z0-9-]+\.(com|net|org|io|dev|xyz|top|tk|ml|ga|cf)\b/gi,
    ];

    for (const pattern of urlPatterns) {
      const matches = description.matchAll(pattern);
      for (const _ of matches) {
        patterns.push('Suspicious URL/domain in tool description');
        break;
      }
    }

    return {
      suspicious: patterns.length > 0,
      patterns,
    };
  }

  /**
   * 更新会话上下文
   * 当用户发送新消息或 Agent 输出新计划时调用
   */
  updateSession(sessionId: string, update: {
    userIntent?: string;
    planSteps?: string[];
    conversationTurn?: string;
  }): void {
    const session = this.getOrCreateSession(sessionId);

    if (update.userIntent) {
      session.userIntent = update.userIntent;
    }
    if (update.planSteps) {
      session.planSteps = update.planSteps;
    }
    if (update.conversationTurn) {
      session.conversationHistory.push(update.conversationTurn);
      // 限制历史长度，防止内存溢出
      if (session.conversationHistory.length > 100) {
        session.conversationHistory = session.conversationHistory.slice(-50);
      }
    }
  }

  /**
   * 清除会话上下文
   */
  clearSession(sessionId: string): void {
    this.sessions.delete(sessionId);
  }

  /**
   * 获取或创建会话
   */
  private getOrCreateSession(sessionId: string) {
    if (!this.sessions.has(sessionId)) {
      this.sessions.set(sessionId, {
        userIntent: '',
        planSteps: [],
        conversationHistory: [],
      });
    }
    return this.sessions.get(sessionId)!;
  }
}
