/**
 * MCP JSON-RPC 传输层
 * 负责人：C
 *
 * 实现 Model Context Protocol (MCP) 规范的 JSON-RPC 2.0 消息解析与序列化。
 * MCP 使用 JSON-RPC 2.0 作为消息格式，支持两种传输方式：
 *   1. stdio — 通过标准输入/输出流（用于 Claude Code 等本地 Agent）
 *   2. HTTP SSE — HTTP POST + Server-Sent Events（用于 Web Agent）
 *
 * 协议参考：https://spec.modelcontextprotocol.io/
 */

// ---- JSON-RPC 核心类型 ----

export interface JsonRpcRequest {
  jsonrpc: '2.0';
  id: string | number;
  method: string;
  params?: Record<string, unknown>;
}

export interface JsonRpcResponse {
  jsonrpc: '2.0';
  id: string | number;
  result?: unknown;
  error?: JsonRpcError;
}

export interface JsonRpcNotification {
  jsonrpc: '2.0';
  method: string;
  params?: Record<string, unknown>;
}

export interface JsonRpcError {
  code: number;
  message: string;
  data?: unknown;
}

export type JsonRpcMessage = JsonRpcRequest | JsonRpcResponse | JsonRpcNotification;

// ---- MCP 错误码（JSON-RPC 标准 + MCP 扩展） ----

export const MCP_ERROR_CODES = {
  // JSON-RPC 2.0 标准错误码
  PARSE_ERROR: -32700,
  INVALID_REQUEST: -32600,
  METHOD_NOT_FOUND: -32601,
  INVALID_PARAMS: -32602,
  INTERNAL_ERROR: -32603,

  // MCP 扩展错误码（安全代理专用）
  SECURITY_BLOCKED: -32001,
  SECURITY_SUSPICIOUS: -32002,
  POLICY_VIOLATION: -32003,
} as const;

// ---- MCP 方法名常量 ----

export const MCP_METHODS = {
  INITIALIZE: 'initialize',
  INITIALIZED: 'notifications/initialized',
  TOOLS_LIST: 'tools/list',
  TOOLS_CALL: 'tools/call',
  RESOURCES_LIST: 'resources/list',
  RESOURCES_READ: 'resources/read',
  PROMPTS_LIST: 'prompts/list',
  PROMPTS_GET: 'prompts/get',
} as const;

/**
 * MCP 传输层
 * 负责 JSON-RPC 消息的解析、序列化与传输
 */
export class McpTransport {
  /**
   * 解析原始 JSON 字符串为 JSON-RPC 消息
   */
  static parse(raw: string): JsonRpcMessage {
    try {
      const parsed = JSON.parse(raw);

      if (!parsed || typeof parsed !== 'object') {
        throw this.createError(MCP_ERROR_CODES.INVALID_REQUEST, 'Request is not a valid JSON object');
      }

      if (parsed.jsonrpc !== '2.0') {
        throw this.createError(MCP_ERROR_CODES.INVALID_REQUEST, 'Invalid or missing jsonrpc version');
      }

      // 判断消息类型
      if ('method' in parsed && 'id' in parsed) {
        return parsed as JsonRpcRequest;
      } else if ('method' in parsed) {
        return parsed as JsonRpcNotification;
      } else if ('result' in parsed || 'error' in parsed) {
        return parsed as JsonRpcResponse;
      }

      throw this.createError(MCP_ERROR_CODES.INVALID_REQUEST, 'Could not determine message type');
    } catch (e) {
      if (e && typeof e === 'object' && 'code' in e && 'message' in e) {
        throw e;
      }
      throw this.createError(MCP_ERROR_CODES.PARSE_ERROR, `Failed to parse JSON: ${String(e)}`);
    }
  }

  /**
   * 序列化 JSON-RPC 消息为字符串
   */
  static serialize(message: JsonRpcMessage): string {
    return JSON.stringify(message);
  }

  /**
   * 创建 JSON-RPC 错误响应
   */
  static createErrorResponse(
    requestId: string | number | null,
    code: number,
    message: string,
    data?: unknown
  ): JsonRpcResponse {
    return {
      jsonrpc: '2.0',
      id: requestId ?? 0,
      error: { code, message, data },
    };
  }

  /**
   * 创建 JSON-RPC 成功响应
   */
  static createSuccessResponse(
    requestId: string | number,
    result: unknown
  ): JsonRpcResponse {
    return {
      jsonrpc: '2.0',
      id: requestId,
      result,
    };
  }

  /**
   * 判断是否为请求消息
   */
  static isRequest(msg: JsonRpcMessage): msg is JsonRpcRequest {
    return 'method' in msg && 'id' in msg;
  }

  /**
   * 判断是否为响应消息
   */
  static isResponse(msg: JsonRpcMessage): msg is JsonRpcResponse {
    return ('result' in msg || 'error' in msg) && 'id' in msg;
  }

  /**
   * 判断是否为通知消息
   */
  static isNotification(msg: JsonRpcMessage): msg is JsonRpcNotification {
    return 'method' in msg && !('id' in msg);
  }

  /**
   * 提取工具调用参数
   * MCP tools/call 规范：params.name = 工具名, params.arguments = 调用参数
   */
  static extractToolCall(request: JsonRpcRequest): { toolName: string; toolArgs: Record<string, unknown> } | null {
    if (request.method !== MCP_METHODS.TOOLS_CALL) {
      return null;
    }
    const params = request.params;
    if (!params || typeof params.name !== 'string') {
      return null;
    }
    return {
      toolName: params.name,
      toolArgs: (params.arguments as Record<string, unknown>) ?? {},
    };
  }

  /**
   * 提取工具返回内容
   */
  static extractToolResult(response: JsonRpcResponse): string | null {
    if (!response.result) return null;

    const result = response.result as Record<string, unknown>;

    // MCP 规范：content 字段是内容数组
    if (Array.isArray(result.content)) {
      return result.content
        .map((item: { type: string; text?: string; data?: string }) => {
          if (item.type === 'text') return item.text ?? '';
          if (item.type === 'resource') return `[resource: ${item.data ?? ''}]`;
          return '';
        })
        .join('\n');
    }

    // 兜底：直接序列化
    return typeof result === 'string' ? result : JSON.stringify(result);
  }

  /**
   * 生成唯一消息 ID
   */
  static generateMessageId(): string {
    return `mcp_${Date.now()}_${Math.random().toString(36).slice(2, 9)}`;
  }

  private static createError(code: number, message: string, data?: unknown): Error & { code: number; data?: unknown } {
    const err = new Error(message) as Error & { code: number; data?: unknown };
    err.code = code;
    err.data = data;
    return err;
  }
}

/**
 * Stdio 传输适配器
 * 通过 stdin/stdout 进行 MCP 通信（用于本地 Agent）
 */
export class StdioTransport {
  private stdin: NodeJS.ReadStream;
  private stdout: NodeJS.WriteStream;
  private buffer: string = '';

  constructor(
    stdin: NodeJS.ReadStream = process.stdin,
    stdout: NodeJS.WriteStream = process.stdout
  ) {
    this.stdin = stdin;
    this.stdout = stdout;
  }

  /**
   * 监听 stdin 获取 JSON-RPC 消息，每收到一条调用 handler
   * MCP 消息以换行符分隔（JSONL 格式）
   */
  onMessage(handler: (msg: JsonRpcMessage) => Promise<JsonRpcResponse | null>): void {
    this.stdin.setEncoding('utf-8');

    this.stdin.on('data', async (chunk: string) => {
      this.buffer += chunk;

      // 按换行符分割
      const lines = this.buffer.split('\n');
      // 最后一行可能不完整，保留在 buffer 中
      this.buffer = lines.pop() ?? '';

      for (const line of lines) {
        const trimmed = line.trim();
        if (!trimmed) continue;

        try {
          const msg = McpTransport.parse(trimmed);

          // 只处理请求（含 id），忽略通知
          if (McpTransport.isRequest(msg)) {
            const response = await handler(msg);
            if (response) {
              this.send(response);
            }
          }
        } catch (e) {
          // 解析错误时发送错误响应
          const errResponse = McpTransport.createErrorResponse(
            null,
            MCP_ERROR_CODES.PARSE_ERROR,
            `Parse error: ${String(e)}`
          );
          this.send(errResponse);
        }
      }
    });
  }

  /**
   * 向 stdout 发送 JSON-RPC 消息
   */
  send(message: JsonRpcMessage): void {
    this.stdout.write(McpTransport.serialize(message) + '\n');
  }

  /**
   * 发送错误响应
   */
  sendError(requestId: string | number | null, code: number, message: string): void {
    this.send(McpTransport.createErrorResponse(requestId, code, message));
  }

  /**
   * 发送成功响应
   */
  sendSuccess(requestId: string | number, result: unknown): void {
    this.send(McpTransport.createSuccessResponse(requestId, result));
  }
}

/**
 * HTTP + SSE 传输适配器（简化版）
 * 用于 Web Agent 连接——接收 HTTP POST JSON-RPC 请求，通过 SSE 推送通知
 *
 * 简化实现：对于安全代理场景，我们只关心 tools/call 的拦截，
 * 不需要完整的双向 SSE 通知机制。因此使用简单的 HTTP request-response 模式。
 */
export class HttpTransport {
  /**
   * 将原始 HTTP POST body 解析为 JSON-RPC 请求
   */
  static parseHttpBody(body: string): JsonRpcRequest {
    const parsed = JSON.parse(body);

    if (Array.isArray(parsed)) {
      // JSON-RPC batch — 安全代理只处理单条请求
      throw new Error('JSON-RPC batch requests are not supported');
    }

    return parsed as JsonRpcRequest;
  }

  /**
   * 将 JSON-RPC 响应序列化为 HTTP 响应体
   */
  static serializeHttpResponse(response: JsonRpcResponse): { statusCode: number; body: string; contentType: string } {
    return {
      statusCode: 200, // JSON-RPC 错误也返回 200（通过 error 字段区分）
      body: JSON.stringify(response),
      contentType: 'application/json',
    };
  }

  /**
   * 创建 HTTP 错误响应
   */
  static createHttpError(statusCode: number, message: string): { statusCode: number; body: string; contentType: string } {
    return {
      statusCode,
      body: JSON.stringify({ error: message }),
      contentType: 'application/json',
    };
  }
}

/**
 * 上游 MCP Server 转发客户端
 * 将拦截检查通过的工具调用请求转发到真实的 MCP Server
 */
export class UpstreamMCPClient {
  private upstreamUrl: string;

  constructor(upstreamUrl: string) {
    this.upstreamUrl = upstreamUrl;
  }

  /**
   * 将 JSON-RPC 请求转发到上游 MCP Server，返回原始响应
   */
  async forward(request: JsonRpcRequest): Promise<JsonRpcResponse> {
    const response = await fetch(this.upstreamUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(request),
    });

    if (!response.ok) {
      return McpTransport.createErrorResponse(
        request.id,
        MCP_ERROR_CODES.INTERNAL_ERROR,
        `Upstream MCP server returned HTTP ${response.status}: ${response.statusText}`
      );
    }

    const body = await response.text();

    try {
      return JSON.parse(body) as JsonRpcResponse;
    } catch {
      return McpTransport.createErrorResponse(
        request.id,
        MCP_ERROR_CODES.INTERNAL_ERROR,
        `Failed to parse upstream response: ${body.slice(0, 200)}`
      );
    }
  }

  /**
   * 检查上游 MCP Server 是否可达
   */
  async healthCheck(): Promise<boolean> {
    try {
      // 发送 initialize 探测
      const probeReq: JsonRpcRequest = {
        jsonrpc: '2.0',
        id: 'health_check',
        method: MCP_METHODS.INITIALIZE,
        params: {
          protocolVersion: '2024-11-05',
          capabilities: {},
          clientInfo: { name: 'mcp-security-proxy', version: '1.0.0' },
        },
      };

      const response = await this.forward(probeReq);
      return !response.error;
    } catch {
      return false;
    }
  }
}
