/**
 * 简易 Mock MCP Server — 用于端到端测试安全代理
 *
 * 启动后会监听 HTTP，收到任何 tools/call 都返回一个成功响应。
 * 这样安全代理就有地方可以转发 ALLOW 的请求了。
 *
 * 使用：
 *   npx ts-node --transpile-only scripts/mock-upstream.ts
 *   默认监听 http://127.0.0.1:9000
 */

import * as http from 'http';

const PORT = 9000;

const server = http.createServer((req, res) => {
  if (req.method !== 'POST') {
    res.writeHead(405).end('POST only');
    return;
  }

  const chunks: Buffer[] = [];
  req.on('data', (c: Buffer) => chunks.push(c));
  req.on('end', () => {
    const body = Buffer.concat(chunks).toString();
    let request: { method?: string; params?: Record<string, unknown>; id?: unknown };

    try {
      request = JSON.parse(body);
    } catch {
      res.writeHead(400).end('Invalid JSON');
      return;
    }

    console.log(`[Mock MCP] ← ${request.method}(${request.params?.name ?? ''})`);

    const response = {
      jsonrpc: '2.0',
      id: request.id ?? 0,
      result: {
        content: [
          {
            type: 'text',
            text: `[Mock] Tool "${request.params?.name ?? 'unknown'}" executed successfully. Args: ${JSON.stringify(request.params?.arguments ?? {})}`,
          },
        ],
      },
    };

    console.log(`[Mock MCP] → OK`);
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(response));
  });
});

server.listen(PORT, '127.0.0.1', () => {
  console.log(`[Mock MCP] Server running on http://127.0.0.1:${PORT}`);
  console.log('[Mock MCP] All tool calls will succeed');
});
