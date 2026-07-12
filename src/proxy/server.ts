/**
 * MCP Security Proxy — 服务器入口
 * 负责人：C
 *
 * 启动 MCP 安全代理服务器，支持两种传输模式：
 *   1. stdio 模式：用于 Claude Code 等本地 Agent（默认）
 *   2. HTTP 模式：用于 Web Agent 通过 HTTP POST 调用
 *
 * 用法：
 *   # stdio 模式（Claude Code 集成）
 *   node dist/proxy/server.js --mode stdio --config config/local.yaml
 *
 *   # HTTP 模式（Web Agent 集成）
 *   node dist/proxy/server.js --mode http --port 9001 --config config/local.yaml
 */

import * as http from 'http';
import * as fs from 'fs';
import * as path from 'path';
import * as yaml from 'js-yaml';
import { McpSecurityProxy, ProxyConfig } from './middleware';
import { JsonRpcRequest, McpTransport, StdioTransport, HttpTransport, MCP_METHODS, MCP_ERROR_CODES } from './mcp-transport';

/**
 * 从 YAML 文件加载配置
 */
function loadConfig(configPath: string): ProxyConfig {
  const raw = fs.readFileSync(configPath, 'utf-8');
  const parsed = yaml.load(raw) as Record<string, unknown>;

  const proxy = (parsed.proxy ?? {}) as Record<string, unknown>;
  const policy = (parsed.policy ?? {}) as Record<string, unknown>;
  const tracing = (parsed.tracing ?? {}) as Record<string, unknown>;

  return {
    upstreamMcpUrl: (proxy.upstream_mcp_url as string) ?? 'http://localhost:9000',
    policyConfigPath: (policy.rules_dir as string) ?? './src/policy/policies',
    auditLogPath: (tracing.audit_log_path as string) ?? './logs/audit.jsonl',
    listenPort: (proxy.listen_port as number) ?? 9001,
    listenHost: (proxy.listen_host as string) ?? '127.0.0.1',
    defaultAction: (policy.default_action as ProxyConfig['defaultAction']) ?? 'ASK_USER',
    verbose: true,
  };
}

/**
 * 启动 stdio 模式代理
 * 用于集成 Claude Code 等本地 MCP 客户端
 */
function startStdioServer(config: ProxyConfig): void {
  const proxy = new McpSecurityProxy(config);
  const transport = new StdioTransport();

  // 记录会话上下文（stdio 模式下会话通常只有一个）
  const SESSION_ID = 'stdio-session';

  transport.onMessage(async (msg) => {
    if (!McpTransport.isRequest(msg)) {
      return null; // 忽略通知和非请求消息
    }

    const method = msg.method;

    try {
      switch (method) {
        case MCP_METHODS.INITIALIZE: {
          // initialize 请求 — 返回代理的能力声明
          return McpTransport.createSuccessResponse(msg.id, {
            protocolVersion: '2024-11-05',
            capabilities: {
              tools: {},
              resources: {},
              prompts: {},
            },
            serverInfo: {
              name: 'mcp-security-proxy',
              version: '1.0.0',
            },
          });
        }

        case MCP_METHODS.TOOLS_LIST: {
          // tools/list — 转发到上游，获取真实工具列表
          try {
            const upstreamResponse = await proxy['upstreamClient'].forward(msg);
            return upstreamResponse;
          } catch {
            return McpTransport.createErrorResponse(
              msg.id,
              MCP_ERROR_CODES.INTERNAL_ERROR,
              'Failed to fetch tool list from upstream MCP server'
            );
          }
        }

        case MCP_METHODS.TOOLS_CALL: {
          // tools/call — 核心拦截点，走完整安全管道
          return await proxy.handleToolCall(msg, SESSION_ID);
        }

        case MCP_METHODS.RESOURCES_LIST:
        case MCP_METHODS.RESOURCES_READ:
        case MCP_METHODS.PROMPTS_LIST:
        case MCP_METHODS.PROMPTS_GET: {
          // 资源/提示词读取 — 转发到上游
          try {
            const upstreamResponse = await proxy['upstreamClient'].forward(msg);
            return upstreamResponse;
          } catch {
            return McpTransport.createErrorResponse(
              msg.id,
              MCP_ERROR_CODES.INTERNAL_ERROR,
              `Failed to forward ${method} to upstream MCP server`
            );
          }
        }

        default: {
          return McpTransport.createErrorResponse(
            msg.id,
            MCP_ERROR_CODES.METHOD_NOT_FOUND,
            `Unknown method: ${method}`
          );
        }
      }
    } catch (err) {
      return McpTransport.createErrorResponse(
        msg.id,
        MCP_ERROR_CODES.INTERNAL_ERROR,
        `Proxy error: ${String(err)}`
      );
    }
  });

  proxy.start().then(() => {
    console.error('[Proxy] MCP Security Proxy running in stdio mode');
    console.error(`[Proxy] Upstream: ${config.upstreamMcpUrl}`);
    console.error('[Proxy] Waiting for MCP client connection...');
  });

  // 优雅退出
  process.on('SIGINT', async () => {
    console.error('\n[Proxy] Shutting down...');
    await proxy.stop();
    process.exit(0);
  });

  process.on('SIGTERM', async () => {
    await proxy.stop();
    process.exit(0);
  });
}

/**
 * 启动 HTTP 模式代理
 * 用于集成 Web Agent 通过 HTTP POST 调用 MCP
 */
function startHttpServer(config: ProxyConfig): void {
  const proxy = new McpSecurityProxy(config);
  const port = config.listenPort ?? 9001;
  const host = config.listenHost ?? '127.0.0.1';

  const server = http.createServer(async (req, res) => {
    // 只接受 POST 请求
    if (req.method !== 'POST') {
      res.writeHead(405, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Method not allowed. Use POST.' }));
      return;
    }

    // 读取 body
    const chunks: Buffer[] = [];
    for await (const chunk of req) {
      chunks.push(Buffer.from(chunk));
    }
    const body = Buffer.concat(chunks).toString('utf-8');

    try {
      const request = HttpTransport.parseHttpBody(body);
      const sessionId = (req.headers['x-session-id'] as string) ?? 'http-session';

      // 提取用户意图（如果通过自定义 Header 传递）
      const userIntent = req.headers['x-user-intent'] as string | undefined;
      if (userIntent) {
        proxy.updateSession(sessionId, userIntent);
      }

      const response = await proxy.handleToolCall(request, sessionId);

      const httpResponse = HttpTransport.serializeHttpResponse(response);
      res.writeHead(httpResponse.statusCode, {
        'Content-Type': httpResponse.contentType,
        'X-Decision': (response.result as Record<string, unknown>)?._decision as string ?? 'ALLOW',
      });
      res.end(httpResponse.body);

    } catch (parseErr) {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        jsonrpc: '2.0',
        id: null,
        error: {
          code: MCP_ERROR_CODES.PARSE_ERROR,
          message: `Failed to parse request: ${String(parseErr)}`,
        },
      }));
    }
  });

  proxy.start().then(() => {
    server.listen(port, host, () => {
      console.error(`[Proxy] MCP Security Proxy running in HTTP mode on http://${host}:${port}`);
      console.error(`[Proxy] Upstream: ${config.upstreamMcpUrl}`);
      console.error(`[Proxy] Send POST requests to http://${host}:${port}/`);
    });
  });

  // 优雅退出
  const shutdown = async () => {
    console.error('\n[Proxy] Shutting down...');
    await proxy.stop();
    server.close();
    process.exit(0);
  };

  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);
}

// ---- 入口 ----

function main(): void {
  const args = process.argv.slice(2);
  const modeFlag = args.indexOf('--mode');
  const mode = modeFlag >= 0 ? args[modeFlag + 1] : 'stdio';
  const configFlag = args.indexOf('--config');
  const configPath = configFlag >= 0 ? args[configFlag + 1] : 'config/default.yaml';
  const portFlag = args.indexOf('--port');
  const portOverride = portFlag >= 0 ? parseInt(args[portFlag + 1], 10) : undefined;

  // 检查配置文件是否存在
  if (!fs.existsSync(configPath)) {
    console.error(`Error: Config file not found: ${configPath}`);
    console.error('Create one by copying config/default.yaml to config/local.yaml');
    process.exit(1);
  }

  const config = loadConfig(configPath);
  if (portOverride) {
    config.listenPort = portOverride;
  }

  // 确保日志目录存在
  const logDir = path.dirname(config.auditLogPath);
  if (!fs.existsSync(logDir)) {
    fs.mkdirSync(logDir, { recursive: true });
  }

  switch (mode) {
    case 'http':
      startHttpServer(config);
      break;
    case 'stdio':
    default:
      startStdioServer(config);
      break;
  }
}

main();
