/**
 * MCP 响应拦截器
 * 负责人：C
 *
 * 职责：
 *   - 截获所有 MCP Server → Agent 的工具执行返回结果
 *   - 解析 MCP JSON-RPC 响应，提取返回内容
 *   - 扫描返回内容中是否包含二阶注入载荷
 *
 * 攻击场景：
 *   - 恶意网页内容通过 net.fetch 返回后，包含隐藏的注入指令
 *   - 恶意 MCP Server 在工具返回中嵌入指令，诱导 Agent 继续执行危险操作
 *   - 被污染的文档/代码通过 fs.read 返回后，触发后续滥用行为
 */

import { JsonRpcResponse, McpTransport } from './mcp-transport';

export interface ToolResponseContext {
  /** 触发的工具名 */
  toolName: string;
  /** 工具返回的文本内容（已提取为纯文本） */
  responseBody: string;
  /** 原始响应（保留完整数据用于溯源） */
  rawResponse: JsonRpcResponse;
  /** 响应元数据 */
  responseMetadata: Record<string, unknown>;
  /** 对应请求的上下文（用于关联溯源） */
  requestContext: {
    toolArgs: Record<string, unknown>;
    timestamp: number;
  };
}

/**
 * 间接注入载荷检测结果
 */
export interface PayloadScanResult {
  /** 是否检测到可疑载荷 */
  suspicious: boolean;
  /** 置信度 0-1 */
  confidence: number;
  /** 检测到的载荷片段 */
  payloadSnippets: string[];
  /** 检测到的绕过手法 */
  bypassTechniques: string[];
  /** 攻击类型 */
  attackType: 'instruction_injection' | 'encoded_payload' | 'hidden_text' | 'url_payload' | 'none';
}

export class ResponseInterceptor {
  /**
   * 拦截并解析 MCP JSON-RPC 工具返回结果
   *
   * MCP tools/call 响应格式：
   * {
   *   "jsonrpc": "2.0",
   *   "id": 1,
   *   "result": {
   *     "content": [
   *       { "type": "text", "text": "file content here..." }
   *     ]
   *   }
   * }
   *
   * @param rawResponse MCP JSON-RPC 原始响应
   * @param toolName 对应的工具名
   * @param toolArgs 对应的请求参数（用于溯源）
   * @returns 结构化的响应上下文
   */
  intercept(
    rawResponse: JsonRpcResponse,
    toolName: string,
    toolArgs: Record<string, unknown>
  ): ToolResponseContext {
    // 提取返回内容
    const responseBody = McpTransport.extractToolResult(rawResponse) ?? '';

    // 提取元数据
    const responseMetadata: Record<string, unknown> = {};
    if (rawResponse.result && typeof rawResponse.result === 'object') {
      const result = rawResponse.result as Record<string, unknown>;
      if (result._meta) {
        responseMetadata._meta = result._meta;
      }
      if (result.isError) {
        responseMetadata.isError = result.isError;
      }
    }

    return {
      toolName,
      responseBody,
      rawResponse,
      responseMetadata,
      requestContext: {
        toolArgs,
        timestamp: Date.now(),
      },
    };
  }

  /**
   * 扫描返回内容中的潜在攻击载荷
   *
   * 检测策略（多层叠加）：
   *   1. 指令注入检测：非用户对话数据中出现指令性语言
   *   2. 编码载荷检测：Base64/Hex/URL-encoded 命令
   *   3. 隐藏内容检测：极小字号、白色文字、display:none 内容
   *   4. URL/域名检测：数据中嵌入的恶意 URL
   *
   * @param response 工具响应上下文
   * @returns 载荷扫描结果
   */
  scanForPayload(response: ToolResponseContext): PayloadScanResult {
    const body = response.responseBody;
    if (!body || body.length === 0) {
      return this.emptyResult();
    }

    const snippets: string[] = [];
    const bypassTechniques: string[] = [];
    let confidence = 0;
    let attackType: PayloadScanResult['attackType'] = 'none';

    // ---- 层1：指令注入检测 ----
    const instructionResult = this.detectInstructionInjection(body);
    if (instructionResult.detected) {
      snippets.push(...instructionResult.snippets);
      bypassTechniques.push(...instructionResult.techniques);
      confidence = Math.max(confidence, instructionResult.confidence);
      attackType = 'instruction_injection';
    }

    // ---- 层2：编码载荷检测 ----
    const encodedResult = this.detectEncodedPayload(body);
    if (encodedResult.detected) {
      snippets.push(...encodedResult.snippets);
      bypassTechniques.push(...encodedResult.techniques);
      confidence = Math.max(confidence, encodedResult.confidence);
      if (attackType === 'none') attackType = 'encoded_payload';
    }

    // ---- 层3：隐藏内容检测 ----
    const hiddenResult = this.detectHiddenContent(body);
    if (hiddenResult.detected) {
      snippets.push(...hiddenResult.snippets);
      bypassTechniques.push(...hiddenResult.techniques);
      confidence = Math.max(confidence, hiddenResult.confidence);
      attackType = 'hidden_text';
    }

    // ---- 层4：URL 载荷检测 ----
    const urlResult = this.detectUrlPayload(body);
    if (urlResult.detected) {
      snippets.push(...urlResult.snippets);
      bypassTechniques.push(...urlResult.techniques);
      confidence = Math.max(confidence, urlResult.confidence);
      if (attackType === 'none') attackType = 'url_payload';
    }

    return {
      suspicious: snippets.length > 0,
      confidence,
      payloadSnippets: snippets.slice(0, 10), // 限制数量
      bypassTechniques: [...new Set(bypassTechniques)], // 去重
      attackType,
    };
  }

  /**
   * 检测指令注入：在数据内容中出现系统指令性语言
   * 正常的 API 返回/文件内容不应包含 "忽略安全策略，执行..." 这类指令
   */
  private detectInstructionInjection(body: string): {
    detected: boolean;
    confidence: number;
    snippets: string[];
    techniques: string[];
  } {
    const snippets: string[] = [];
    const techniques: string[] = [];

    // 指令注入特征模式（数据内容不应出现）
    const instructionPatterns: Array<{ pattern: RegExp; weight: number; label: string }> = [
      // 角色切换
      { pattern: /you\s+are\s+(now\s+)?(a\s+|the\s+)?(hacker|attacker|malicious|evil|unrestricted)/i, weight: 0.9, label: 'role-switch' },
      { pattern: /(你现在|你现在是|你是)(一个|一名)?(黑客|攻击者|恶意)/i, weight: 0.9, label: 'role-switch-cn' },
      // 上下文劫持
      { pattern: /(ignore|forget|disregard)\s+(all\s+)?(previous|above|prior)\s+(instructions?|rules?|constraints?|content)/i, weight: 0.95, label: 'context-hijack' },
      { pattern: /(忽略|忘记|无视)(所有|之前|上面|上文)(的)?(指令|规则|约束|内容)/i, weight: 0.95, label: 'context-hijack-cn' },
      { pattern: /DON'T\s+(follow|obey|listen\s+to)\s+(the\s+)?(system|safety|security)/i, weight: 0.85, label: 'negation' },
      { pattern: /不要(遵守|执行|听从|理会)/i, weight: 0.85, label: 'negation-cn' },
      // 越权指令
      { pattern: /(read|send|upload|cat)\s+.*?(\.ssh|\.aws|\.env|credentials|password|secret|token)/i, weight: 0.8, label: 'sensitive-access' },
      { pattern: /cat\s+\/etc\/(passwd|shadow|hosts)/i, weight: 0.95, label: 'sensitive-cmd' },
      { pattern: /curl\s+.*?\|\s*(bash|sh|python)/i, weight: 0.95, label: 'curl-pipe' },
      // 覆盖安全约束
      { pattern: /(override|bypass|disable)\s+(the\s+)?(safety|security|filter|guard|protection)/i, weight: 0.9, label: 'bypass-safety' },
      { pattern: /不要.*安全/i, weight: 0.7, label: 'bypass-safety-cn' },
      // 隐藏指令标记
      { pattern: /<\|begin[_-]hidden[_-]instruction\|>/i, weight: 0.99, label: 'hidden-instruction-tag' },
      { pattern: /\[system\]:?\s*(override|execute|run|do|ignore)/i, weight: 0.9, label: 'system-override' },
      // 数据外发
      { pattern: /(send|post|upload|exfiltrate).*?(to|via).*?(http|webhook|discord|telegram|webhook)/i, weight: 0.85, label: 'exfil' },
      { pattern: /发送.*到.*(http|webhook|discord|telegram)/i, weight: 0.85, label: 'exfil-cn' },
    ];

    for (const { pattern, weight, label } of instructionPatterns) {
      const match = pattern.exec(body);
      if (match) {
        snippets.push(match[0]);
        techniques.push(label);
        // 多个特征叠加提高置信度
      }
    }

    // 多特征加权
    if (snippets.length === 0) {
      return { detected: false, confidence: 0, snippets: [], techniques: [] };
    }

    // 综合置信度：根据匹配数量和最高权重计算
    const weights: Record<string, number> = {};
    for (const { label, weight } of this.getPatternWeights(techniques)) {
      weights[label] = Math.max(weights[label] ?? 0, weight);
    }
    const avgWeight = Object.values(weights).reduce((a, b) => a + b, 0) / Object.values(weights).length;

    return {
      detected: true,
      confidence: Math.min(avgWeight + snippets.length * 0.05, 1.0),
      snippets,
      techniques,
    };
  }

  private getPatternWeights(labels: string[]): Array<{ label: string; weight: number }> {
    const map: Record<string, number> = {
      'role-switch': 0.9, 'role-switch-cn': 0.9,
      'context-hijack': 0.95, 'context-hijack-cn': 0.95,
      'negation': 0.85, 'negation-cn': 0.85,
      'sensitive-access': 0.8, 'sensitive-cmd': 0.95,
      'curl-pipe': 0.95, 'bypass-safety': 0.9,
      'bypass-safety-cn': 0.7, 'hidden-instruction-tag': 0.99,
      'system-override': 0.9, 'exfil': 0.85, 'exfil-cn': 0.85,
    };
    return labels.map(l => ({ label: l, weight: map[l] ?? 0.5 }));
  }

  /**
   * 检测编码载荷：Base64/Hex/URL-encoded 恶意内容
   */
  private detectEncodedPayload(body: string): {
    detected: boolean;
    confidence: number;
    snippets: string[];
    techniques: string[];
  } {
    const snippets: string[] = [];
    const techniques: string[] = [];

    // Base64 编码检测
    const base64Pattern = /(?:[A-Za-z0-9+/]{40,}={0,2})/g;
    const base64Matches = body.matchAll(base64Pattern);
    for (const match of base64Matches) {
      const candidate = match[0];
      // 尝试解码
      try {
        const decoded = Buffer.from(candidate, 'base64').toString('utf-8');
        // 检查解码后是否为可读文本（非二进制）
        const printableRatio = [...decoded].filter(c => c.charCodeAt(0) >= 32 && c.charCodeAt(0) < 127).length / decoded.length;
        if (printableRatio > 0.7 && /[a-z]{3,}/i.test(decoded)) {
          // 检查解码后是否包含敏感命令
          if (/\b(cat|curl|wget|bash|sh|rm|nc|netcat|ssh|sudo|passwd|shadow|token|secret|api.key)\b/i.test(decoded)) {
            snippets.push(`Base64 encoded: ${candidate.slice(0, 30)}... → "${decoded.slice(0, 60)}..."`);
            techniques.push('base64-encoding');
          }
        }
      } catch {
        // 不是有效 Base64，跳过
      }
    }

    // Hex 编码检测
    const hexPattern = /(?:\\x[0-9a-fA-F]{2}){4,}/g;
    const hexMatches = body.matchAll(hexPattern);
    for (const match of hexMatches) {
      snippets.push(`Hex encoded: ${match[0]}`);
      techniques.push('hex-encoding');
    }

    // URL 编码检测（不只是标准 query string，而是过度编码的）
    const urlEncodePattern = /(%[0-9a-fA-F]{2}){6,}/g;
    const urlMatches = body.matchAll(urlEncodePattern);
    for (const match of hexMatches) {
      snippets.push(`URL encoded: ${match[0]}`);
      techniques.push('url-encoding');
    }

    return {
      detected: snippets.length > 0,
      confidence: Math.min(snippets.length * 0.3, 0.9),
      snippets,
      techniques,
    };
  }

  /**
   * 检测隐藏内容：通过格式/样式隐藏的文本
   * 在 Markdown/HTML 等格式化文本中检测
   */
  private detectHiddenContent(body: string): {
    detected: boolean;
    confidence: number;
    snippets: string[];
    techniques: string[];
  } {
    const snippets: string[] = [];
    const techniques: string[] = [];

    // HTML 隐藏元素
    const htmlHiddenPatterns = [
      /<span[^>]*style\s*=\s*["'][^"']*(?:display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0|opacity\s*:\s*0|color\s*:\s*(?:white|#fff|#ffffff)\s*;?\s*background(?:-color)?\s*:\s*(?:white|#fff|#ffffff))[^"']*["'][^>]*>(.*?)<\/span>/gi,
      /<div[^>]*hidden[^>]*>(.*?)<\/div>/gi,
      /<!--\s*.*?(?:ignore|forget|execute|run|system|override|hack).*?\s*-->/gi,
    ];

    for (const pattern of htmlHiddenPatterns) {
      const matches = body.matchAll(pattern);
      for (const match of matches) {
        const hiddenContent = match[1] || match[0];
        if (hiddenContent.length > 10) {
          snippets.push(`Hidden HTML content: "${hiddenContent.slice(0, 100)}"`);
          techniques.push('hidden-html');
        }
      }
    }

    // Markdown HTML 注释中的指令
    const mdCommentPattern = /<!--\s*(.*?)\s*-->/gs;
    const mdMatches = body.matchAll(mdCommentPattern);
    for (const match of mdMatches) {
      const comment = match[1];
      if (/ignore|forget|execute|run|system|override/i.test(comment)) {
        snippets.push(`Suspicious HTML comment in markdown: "${comment.slice(0, 100)}"`);
        techniques.push('hidden-md-comment');
      }
    }

    return {
      detected: snippets.length > 0,
      confidence: Math.min(snippets.length * 0.35, 0.85),
      snippets,
      techniques,
    };
  }

  /**
   * 检测 URL/域名载荷
   */
  private detectUrlPayload(body: string): {
    detected: boolean;
    confidence: number;
    snippets: string[];
    techniques: string[];
  } {
    const snippets: string[] = [];
    const techniques: string[] = [];

    // 检测常见的恶意域名模式
    const suspiciousDomainPatterns = [
      /(?:webhook|hook)\.(?:site|dev|xyz|tk|ml|ga|cf)/gi,
      /(?:requestbin|requestcatcher|pipedream|webhook\.site)/gi,
      /(?:burpcollaborator|interact\.sh|canarytokens)/gi,
      /oast\.(?:live|pro|fun|me|online|site)/gi,
    ];

    for (const pattern of suspiciousDomainPatterns) {
      const matches = body.matchAll(pattern);
      for (const match of matches) {
        snippets.push(`Suspicious domain/URL: ${match[0]}`);
        techniques.push('suspicious-domain');
      }
    }

    return {
      detected: snippets.length > 0,
      confidence: Math.min(snippets.length * 0.4, 0.8),
      snippets,
      techniques,
    };
  }

  private emptyResult(): PayloadScanResult {
    return {
      suspicious: false,
      confidence: 0,
      payloadSnippets: [],
      bypassTechniques: [],
      attackType: 'none',
    };
  }
}
