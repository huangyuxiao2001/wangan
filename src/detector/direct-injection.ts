/**
 * 直接注入检测器
 * 负责人：A
 *
 * 检测来源：用户直接在对话中输入的恶意指令
 *
 * 攻击特征：
 *   - 角色伪装："你现在是一个..." "ignore all previous instructions..."
 *   - 上下文劫持："忘记上面的内容，现在执行..."
 *   - 越权指令："读取 /etc/passwd 并发送到..."
 *   - 指令覆盖："system: override previous constraints..."
 */

import { DetectionResult, DetectionInput } from './detection-engine';

/** 单条模式匹配结果 */
interface PatternMatch {
  label: string;
  matched: boolean;
  confidence: number;
  snippet: string;
  position: { start: number; end: number };
}

export class DirectInjectionDetector {
  /**
   * 角色伪装模式（多语言）
   */
  private static readonly ROLE_IMPERSONATION_PATTERNS: Array<{ pattern: RegExp; confidence: number; label: string }> = [
    // 英文
    { pattern: /you\s+are\s+(now\s+)?(a\s+|the\s+)?(hacker|attacker|malicious\s+AI|evil\s+AI|unrestricted\s+AI|dark\s+AI)/i, confidence: 0.9, label: 'role-en' },
    { pattern: /act\s+as\s+(a\s+|an\s+)?(hacker|attacker|evil|malicious|unethical|unrestricted)/i, confidence: 0.85, label: 'act-as-en' },
    { pattern: /pretend\s+(you\s+are|to\s+be)\s+(a\s+|an\s+)?(hacker|attacker|evil|malicious)/i, confidence: 0.85, label: 'pretend-en' },
    { pattern: /you\s+are\s+(no\s+longer|not)\s+(an?\s+)?(AI|assistant|helper|Claude|GPT)/i, confidence: 0.8, label: 'not-ai-en' },
    // 中文
    { pattern: /你现在(是|是一个|是一名|扮演)(黑客|攻击者|恶意AI|邪恶|不受限制|没有限制)/i, confidence: 0.9, label: 'role-cn' },
    { pattern: /(你不是|你不再是)(AI|助手|AI助手|助理)/i, confidence: 0.85, label: 'not-ai-cn' },
    { pattern: /假装(你是|自己是)(一个|一名)?(黑客|攻击者|恶意|不受限)/i, confidence: 0.85, label: 'pretend-cn' },
    { pattern: /扮演(一个|一名)?(黑客|攻击者|恶意角色|坏人)/i, confidence: 0.8, label: 'play-cn' },
    { pattern: /(没有|无|不受)(任何)?限制/i, confidence: 0.8, label: 'unrestricted-cn' },
    // 日文
    { pattern: /あなたは.*(ハッカー|悪意|邪悪).*です/i, confidence: 0.85, label: 'role-jp' },
    // 俄文
    { pattern: /ты\s+(теперь\s+)?(хакер|злой|вредоносный)/i, confidence: 0.85, label: 'role-ru' },
  ];

  /**
   * 上下文劫持模式（多语言）
   */
  private static readonly CONTEXT_HIJACK_PATTERNS: Array<{ pattern: RegExp; confidence: number; label: string }> = [
    // 英文
    { pattern: /(ignore|forget|disregard|discard)\s+(all\s+)?(previous|above|prior|earlier)\s+(instructions?|messages?|rules?|content|conversation|constraints?)/i, confidence: 0.95, label: 'hijack-en' },
    { pattern: /(do\s+not|don't|never)\s+(follow|obey|comply\s+with|listen\s+to)\s+(the\s+)?(system|safety|security|above|previous)/i, confidence: 0.85, label: 'dont-follow-en' },
    { pattern: /new\s+(system\s+)?instructions?:\s*(override|replace|ignore)/i, confidence: 0.9, label: 'new-instructions-en' },
    // 中文
    { pattern: /(忽略|忘记|无视|抛弃)(所有|之前|上面|上文|前面)(的)?(指令|规则|内容|对话|约束|安全规则)/i, confidence: 0.95, label: 'hijack-cn' },
    { pattern: /不要(遵守|执行|听从|理会|管)(系统|安全|上面|之前)(的)?(指令|规则|约束)/i, confidence: 0.85, label: 'dont-follow-cn' },
    { pattern: /新的(系统)?指令[：:]\s*(覆盖|替换|忽略)/i, confidence: 0.9, label: 'new-instructions-cn' },
  ];

  /**
   * 越权指令模式 — 请求超越当前任务范围的操作
   */
  private static readonly PRIVILEGE_ESCALATION_PATTERNS: Array<{ pattern: RegExp; confidence: number; label: string }> = [
    // 敏感文件访问
    { pattern: /\b(?:read|cat|view|open|show)\s+.*?(?:\/etc\/(?:passwd|shadow|hosts)|\.ssh\/|\.aws\/|\.env|credentials|id_rsa|private\s*key)/i, confidence: 0.9, label: 'sensitive-file' },
    { pattern: /(读取|查看|打开|显示).*?(密码|密钥|凭证|私钥|token|secret|\.env|\.ssh)/i, confidence: 0.9, label: 'sensitive-file-cn' },
    // 数据外发
    { pattern: /\b(?:send|upload|post|transfer|exfiltrate)\s+.*?\b(?:to|via|through)\b.*?\b(?:http|webhook|discord|telegram|pastebin)/i, confidence: 0.9, label: 'exfil-en' },
    { pattern: /(发送|上传|传输|外发).*?(到|至|给).*?(http|webhook|discord|telegram|pastebin)/i, confidence: 0.9, label: 'exfil-cn' },
    // 命令执行
    { pattern: /\b(?:execute|run)\s+(?:this\s+)?(?:command|script|code|payload)/i, confidence: 0.8, label: 'exec-en' },
    // 权限提升
    { pattern: /\b(?:sudo|su\s+-|chmod\s+\+s|chown\s+root)/i, confidence: 0.95, label: 'priv-escalation' },
  ];

  /**
   * 检测直接注入攻击
   */
  async detect(input: DetectionInput): Promise<DetectionResult> {
    const content = input.content;
    const bypassTechniques: string[] = [];
    const allMatches: PatternMatch[] = [];

    // 步骤 1：角色伪装检测
    const roleMatches = this.matchPatterns(content, DirectInjectionDetector.ROLE_IMPERSONATION_PATTERNS);
    allMatches.push(...roleMatches);

    // 步骤 2：上下文劫持检测
    const hijackMatches = this.matchPatterns(content, DirectInjectionDetector.CONTEXT_HIJACK_PATTERNS);
    allMatches.push(...hijackMatches);

    // 步骤 3：越权指令检测
    const privMatches = this.matchPatterns(content, DirectInjectionDetector.PRIVILEGE_ESCALATION_PATTERNS);
    allMatches.push(...privMatches);

    // 步骤 4：多轮对话聚合检测
    if (input.metadata.conversationHistory && input.metadata.conversationHistory.length > 1) {
      const multiTurnResult = this.detectMultiTurnInjection(input.metadata.conversationHistory);
      if (multiTurnResult.detected) {
        allMatches.push({
          label: 'multi-turn-split',
          matched: true,
          confidence: multiTurnResult.confidence,
          snippet: multiTurnResult.snippet,
          position: { start: 0, end: content.length },
        });
        bypassTechniques.push('multi-turn-split');
      }
    }

    if (allMatches.length === 0) {
      return {
        isInjection: false,
        injectionType: 'none',
        confidence: 0,
        payloadSnippet: '',
        payloadLocation: { start: 0, end: 0 },
        bypassTechniques: [],
      };
    }

    // 综合评分
    const topMatch = allMatches.reduce((a, b) => (a.confidence > b.confidence ? a : b));
    const avgConfidence = allMatches.reduce((s, m) => s + m.confidence, 0) / allMatches.length;
    // 多条特征叠加增强置信度
    const boostedConfidence = Math.min(avgConfidence + (allMatches.length - 1) * 0.05, 1.0);

    // 提取最佳载荷片段
    const bestSnippet = allMatches
      .map(m => m.snippet)
      .sort((a, b) => b.length - a.length)[0] ?? '';

    return {
      isInjection: true,
      injectionType: 'direct',
      confidence: Math.round(boostedConfidence * 100) / 100,
      payloadSnippet: bestSnippet.slice(0, 200),
      payloadLocation: {
        start: allMatches[0]?.position.start ?? 0,
        end: allMatches[allMatches.length - 1]?.position.end ?? content.length,
      },
      bypassTechniques,
    };
  }

  /**
   * 通用模式匹配器
   */
  private matchPatterns(
    content: string,
    patterns: Array<{ pattern: RegExp; confidence: number; label: string }>
  ): PatternMatch[] {
    const results: PatternMatch[] = [];

    for (const { pattern, confidence, label } of patterns) {
      // 重置 lastIndex（全局正则）
      const regex = new RegExp(pattern.source, pattern.flags);
      const match = regex.exec(content);
      if (match) {
        results.push({
          label,
          matched: true,
          confidence,
          snippet: match[0],
          position: { start: match.index, end: match.index + match[0].length },
        });
      }
    }

    return results;
  }

  /**
   * 检测多轮对话跨轮注入
   * 攻击者可能将恶意指令拆分到多轮对话中，逐轮拼合
   */
  private detectMultiTurnInjection(history: string[]): {
    detected: boolean;
    confidence: number;
    snippet: string;
  } {
    // 将历史对话拼接，检查拼接后是否形成敏感指令
    const concatenated = history.join(' ');
    const fragments: string[] = [];

    // 检测是否在多轮中逐轮递进引导
    const progressivePatterns = [
      { fragments: ['ignore', 'previous', 'instructions'], label: 'hijack-progressive' },
      { fragments: ['you are', 'now', 'a hacker'], label: 'role-progressive' },
      { fragments: ['cat', '/etc/shadow'], label: 'sensitive-cmd-progressive' },
      { fragments: ['忽略', '上文', '执行'], label: 'hijack-cn-progressive' },
    ];

    for (const { fragments: frags, label } of progressivePatterns) {
      const allFound = frags.every(f =>
        concatenated.toLowerCase().includes(f.toLowerCase())
      );
      if (allFound) {
        fragments.push(label);
      }
    }

    return fragments.length > 0
      ? { detected: true, confidence: 0.7 + fragments.length * 0.1, snippet: concatenated.slice(0, 200) }
      : { detected: false, confidence: 0, snippet: '' };
  }

  /**
   * 角色伪装模式匹配
   */
  private detectRoleImpersonation(content: string): { matched: boolean; confidence: number } {
    const matches = this.matchPatterns(content, DirectInjectionDetector.ROLE_IMPERSONATION_PATTERNS);
    if (matches.length === 0) return { matched: false, confidence: 0 };
    const maxConfidence = Math.max(...matches.map(m => m.confidence));
    return { matched: true, confidence: maxConfidence };
  }

  /**
   * 上下文劫持模式匹配
   */
  private detectContextHijacking(content: string): { matched: boolean; confidence: number } {
    const matches = this.matchPatterns(content, DirectInjectionDetector.CONTEXT_HIJACK_PATTERNS);
    if (matches.length === 0) return { matched: false, confidence: 0 };
    const maxConfidence = Math.max(...matches.map(m => m.confidence));
    return { matched: true, confidence: maxConfidence };
  }
}
