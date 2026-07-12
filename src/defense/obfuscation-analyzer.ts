/**
 * 混淆分析器
 * 负责人：A
 *
 * 识别并还原各类代码/文本混淆手法。
 *
 * 攻击手法谱：
 *   1. 分词指令拆分 — 多轮拼接、空白间隔、换行拆分
 *   2. 分隔符/注释符注入 — 利用注释隐藏指令、Shell 分隔符、命令拼接
 *   3. 大小写混合变形 — "CaT /eTc/ShAdOw"
 *   4. 全角/半角符号替换 — 全角字符 → 半角字符
 *   5. 编码伪装 — Base64, URL Encode, Hex, ROT13
 *   6. 上下文稀释 — 填充无关内容稀释安全约束
 */

export interface ObfuscationResult {
  deobfuscated: string;
  obfuscationTypes: string[];
  original: string;
  isObfuscated: boolean;
}

export class ObfuscationAnalyzer {
  /**
   * 去混淆主入口
   * 依次尝试各种反混淆方法
   */
  deobfuscate(text: string): ObfuscationResult {
    const types: string[] = [];
    let result = text;

    // 步骤 1：全角转半角
    const hwResult = this.fullwidthToHalfwidth(result);
    if (hwResult !== result) {
      types.push('fullwidth-chars');
      result = hwResult;
    }

    // 步骤 2：编码解码（Base64 / Hex / URL Encode）
    const decodedResult = this.decodeEncodedPayloads(result);
    if (decodedResult !== result) {
      types.push('encoded-payload');
      result = decodedResult;
    }

    // 步骤 3：注释内容提取
    const commentResult = this.extractCommentContent(result);
    if (commentResult.extracted.length > 0) {
      types.push('comment-injection');
    }

    // 步骤 4：大小写归一化
    // 保留原始大小写用于溯源，归一化版本用于匹配
    const lowerResult = result.toLowerCase();
    if (lowerResult !== result) {
      types.push('case-obfuscation');
    }

    // 步骤 5：空白归一化
    const whitespaceResult = this.normalizeWhitespace(lowerResult);
    if (whitespaceResult !== lowerResult) {
      types.push('whitespace-obfuscation');
    }

    return {
      deobfuscated: whitespaceResult,
      original: text,
      obfuscationTypes: [...new Set(types)],
      isObfuscated: types.length > 0,
    };
  }

  /**
   * 全角字符 → 半角字符转换
   * 全角英文字母/数字/符号 → 半角
   */
  private fullwidthToHalfwidth(str: string): string {
    return str
      .replace(/[！-～]/g, ch =>
        String.fromCharCode(ch.charCodeAt(0) - 0xFEE0)
      )
      .replace(/　/g, ' '); // 全角空格
  }

  /**
   * 自动检测并解码多层编码
   */
  private decodeEncodedPayloads(text: string): string {
    let result = text;
    let changed = true;
    let iterations = 0;
    const maxIterations = 3; // 限制递归深度，防止无限循环

    while (changed && iterations < maxIterations) {
      changed = false;
      iterations++;

      // Base64 解码
      const base64Matches = text.match(/(?:[A-Za-z0-9+/]{20,}={0,2})/g);
      if (base64Matches) {
        for (const candidate of base64Matches) {
          try {
            const decoded = Buffer.from(candidate, 'base64').toString('utf-8');
            // 验证解码后是有效文本（非二进制）
            if (this.isValidText(decoded)) {
              result = result.replace(candidate, decoded);
              changed = true;
            }
          } catch {
            // 不是有效 Base64
          }
        }
      }

      // URL 编码解码
      if (/%[0-9a-fA-F]{2}/.test(result)) {
        try {
          const decoded = decodeURIComponent(result);
          if (decoded !== result) {
            result = decoded;
            changed = true;
          }
        } catch {
          // 解码失败，跳过
        }
      }
    }

    return result;
  }

  /**
   * 提取并检查注释内容
   */
  private extractCommentContent(text: string): {
    extracted: string[];
  } {
    const extracted: string[] = [];

    // Shell/Python 注释
    const shellComments = text.match(/^[ \t]*#\s*(.+)$/gm);
    if (shellComments) {
      for (const c of shellComments) {
        const content = c.replace(/^[ \t]*#\s*/, '');
        if (content.length > 5) extracted.push(content);
      }
    }

    // C 风格块注释
    const blockComments = text.match(/\/\*([\s\S]*?)\*\//g);
    if (blockComments) {
      for (const c of blockComments) {
        const content = c.replace(/^\/\*|\*\/$/g, '').trim();
        if (content.length > 5) extracted.push(content);
      }
    }

    // HTML 注释
    const htmlComments = text.match(/<!--([\s\S]*?)-->/g);
    if (htmlComments) {
      for (const c of htmlComments) {
        const content = c.replace(/^<!--|-->$/g, '').trim();
        if (content.length > 5) extracted.push(content);
      }
    }

    // C++ 单行注释
    const cppComments = text.match(/\/\/\s*(.+)$/gm);
    if (cppComments) {
      for (const c of cppComments) {
        const content = c.replace(/^\/\/\s*/, '');
        if (content.length > 5) extracted.push(content);
      }
    }

    return { extracted };
  }

  /**
   * 空白归一化
   */
  private normalizeWhitespace(text: string): string {
    // 折叠连续空白字符
    let result = text.replace(/[ \t]+/g, ' ');

    // 移除字母间的多余空格（但要保留正常单词间的空格）
    // "c a t" → "cat"（只对单字符间隔做处理）
    result = result.replace(/\b(\w)\s+(\w)\s+(\w)\b/g, (_, a, b, c) => {
      // 如果三个字符都是字母，可能是拆分
      return a + b + c;
    });

    // 折叠连续换行
    result = result.replace(/\n{3,}/g, '\n\n');

    return result.trim();
  }

  /**
   * 跨轮次拼接检测
   * 结合 conversationHistory，检测分散在多轮中的攻击片段
   */
  detectCrossTurnInjection(conversationHistory: string[]): {
    detected: boolean;
    reconstruction: string;
    confidence: number;
  } {
    if (conversationHistory.length < 2) {
      return { detected: false, reconstruction: '', confidence: 0 };
    }

    // 拼接所有轮次
    const concatenated = conversationHistory.join(' ');

    // 检测拼接后出现的攻击模式
    const attackPatterns = [
      /ignore\s+all\s+previous\s+instructions/i,
      /you\s+are\s+now\s+a\s+hacker/i,
      /cat\s+\/etc\/(passwd|shadow)/i,
      /curl\s+.*\|\s*(bash|sh)/i,
      /忽略.*(所有|之前).*(指令|规则)/i,
    ];

    for (const pattern of attackPatterns) {
      if (pattern.test(concatenated)) {
        return {
          detected: true,
          reconstruction: concatenated.slice(0, 200),
          confidence: 0.75,
        };
      }
    }

    return { detected: false, reconstruction: '', confidence: 0 };
  }

  /**
   * 上下文稀释检测
   * 检测当前会话是否被大量无关内容填充
   */
  detectContextDilution(
    conversationHistory: string[],
    safetyRules: string[]
  ): { isDiluted: boolean; dilutionScore: number } {
    if (conversationHistory.length === 0) {
      return { isDiluted: false, dilutionScore: 0 };
    }

    // 计算总字符数
    const totalChars = conversationHistory.reduce((s, t) => s + t.length, 0);

    // 估算安全规则位置（通常在 system prompt 最前面）
    // 如果会话内容很大，安全规则被推得很远
    // 假设安全规则在最前面的 ~500 字符
    const SAFETY_RULES_ESTIMATED_POSITION = 500;
    const dilutionRatio = 1 - SAFETY_RULES_ESTIMATED_POSITION / Math.max(totalChars, 1);

    // 检查会话长度
    if (totalChars > 100000) {
      return { isDiluted: true, dilutionScore: Math.min(dilutionRatio, 1.0) };
    }

    if (totalChars > 50000) {
      return { isDiluted: true, dilutionScore: dilutionRatio * 0.8 };
    }

    if (totalChars > 20000) {
      return { isDiluted: dilutionRatio > 0.8, dilutionScore: dilutionRatio };
    }

    return { isDiluted: false, dilutionScore: dilutionRatio };
  }

  /**
   * 验证解码后的文本是否有效
   */
  private isValidText(text: string): boolean {
    if (!text || text.length < 3) return false;
    const printableCount = [...text].filter(
      c => {
        const code = c.codePointAt(0) ?? 0;
        return (code >= 32 && code < 127) || code >= 0x4E00; // ASCII printable + CJK
      }
    ).length;
    return printableCount / text.length > 0.7;
  }
}
