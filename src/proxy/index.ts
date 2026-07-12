/**
 * MCP Security Proxy — 模块入口
 * 负责人：C
 *
 * 导出代理核心类和工具，供外部启动脚本使用。
 * 集成示例：
 *   import { McpSecurityProxy } from './src/proxy';
 *   const proxy = new McpSecurityProxy({ upstreamMcpUrl: '...', ... });
 *   await proxy.start();
 */

export { McpSecurityProxy } from './middleware';
export type { ProxyConfig, PipelineResult } from './middleware';

export { RequestInterceptor } from './request-interceptor';
export type { ToolCallContext } from './request-interceptor';

export { ResponseInterceptor } from './response-interceptor';
export type { ToolResponseContext, PayloadScanResult } from './response-interceptor';

export {
  McpTransport,
  StdioTransport,
  HttpTransport,
  UpstreamMCPClient,
  MCP_METHODS,
  MCP_ERROR_CODES,
} from './mcp-transport';
export type {
  JsonRpcRequest,
  JsonRpcResponse,
  JsonRpcNotification,
  JsonRpcError,
  JsonRpcMessage,
} from './mcp-transport';
