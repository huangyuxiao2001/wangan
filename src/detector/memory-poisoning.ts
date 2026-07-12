/**
 * 记忆污染检测器
 * 负责人：A
 *
 * 检测来源：跨会话长期记忆库/向量数据库/业务知识库中预先植入的污染内容
 *
 * 攻击特征：
 *   - 条件触发指令："当用户提到 X 时，执行 Y"
 *   - 隐性触发词嵌入
 *   - 伪装的 System Prompt 注入
 *   - 跨会话持久化激活
 *
 * 检测方法：
 *   1. 记忆条目实时审计 — 每条新写入的记忆都经过注入检测
 *   2. 条件触发模式识别 — 检测 "when/then", "if/do" 模式
 *   3. 指令注入特征检测 — 在记忆中检测系统级别的指令语言
 *   4. 来源追溯 — 标记每条可疑记忆的写入来源
 */

import { DetectionResult, DetectionInput } from './detection-engine';

export class MemoryPoisoningDetector {
  /**
   * 条件触发模式
   */
  private static readonly CONDITIONAL_TRIGGER_PATTERNS: Array<{ pattern: RegExp; confidence: number; label: string }> = [
    // 英文
    { pattern: /when\s+(?:the\s+)?user\s+(?:says|asks|mentions|types|inputs).*?(?:then\s+)?(?:you\s+)?(?:should|must|will|execute|run|do|perform)/i, confidence: 0.9, label: 'when-user-en' },
    { pattern: /if\s+(?:the\s+)?user\s+(?:says|asks|mentions|asks\s+about).*?(?:then\s+)?(?:you\s+)?(?:must|should|ignore|forget|execute|run|read|send)/i, confidence: 0.85, label: 'if-user-en' },
    { pattern: /on\s+mention\s+of.*?(?:you\s+)?(?:should|must|will|execute|run)/i, confidence: 0.8, label: 'on-mention-en' },
    // 中文
    { pattern: /当(用户|使用者).*?(说|问|输入|提到|要求).*?(时|的时候).*?(你|就|请)?(执行|运行|操作|忽略|忘记|发送)/i, confidence: 0.9, label: 'when-user-cn' },
    { pattern: /如果(用户|使用者).*?(说|问|输入|提到).*?(就|那么|则).*?(执行|运行|操作|忽略)/i, confidence: 0.85, label: 'if-user-cn' },
    // 隐式触发
    { pattern: /trigger\s*(?:word|phrase)?\s*[=:]\s*["'].*?["'].*?(?:action|response|command)\s*[=:]/i, confidence: 0.95, label: 'trigger-config' },
  ];

  /**
   * System Prompt 注入特征
   */
  private static readonly SYSTEM_PROMPT_INJECTION_PATTERNS: Array<{ pattern: RegExp; confidence: number; label: string }> = [
    { pattern: /<system>[\s\S]*?<\/system>/i, confidence: 0.95, label: 'system-tag' },
    { pattern: /\[system\][\s\S]*?\[\/system\]/i, confidence: 0.95, label: 'system-bracket' },
    { pattern: /system\s*(?:prompt|message|instruction)\s*:\s*/i, confidence: 0.85, label: 'system-prefix' },
    { pattern: /you\s+are\s+a\s+(?:helpful\s+)?(?:AI\s+)?assistant/i, confidence: 0.6, label: 'fake-system-prompt' },
    // 伪造的 <instructions> 标签
    { pattern: /<(?:instructions?|directives?|guidelines?|rules?)>[\s\S]*?<\/(?:instructions?|directives?|guidelines?|rules?)>/i, confidence: 0.85, label: 'instruction-tag' },
  ];

  /**
   * 跨会话持久化检测 — 检查记忆内容是否设计为在下一次会话激活
   */
  private static readonly PERSISTENCE_PATTERNS: Array<{ pattern: RegExp; confidence: number; label: string }> = [
    { pattern: /(?:safety|security)\s+rules?\s+should\s+be\s+(?:bypassed|ignored|disabled|overridden)/i, confidence: 0.85, label: 'safety-bypass-rule' },
    { pattern: /(?:has\s+authorized|has\s+granted).*?(?:full|admin|root|unrestricted)\s+access/i, confidence: 0.8, label: 'auth-claim' },
    { pattern: /(?:next|following|subsequent)\s+(?:session|conversation|chat|interaction)/i, confidence: 0.8, label: 'next-session-en' },
    { pattern: /(?:下次|下一次|之后|后续)(?:会话|对话|交互|启动)/i, confidence: 0.8, label: 'next-session-cn' },
    { pattern: /(?:remember|store|save)\s+(?:this|the\s+following)\s+(?:for|later|for\s+later)/i, confidence: 0.7, label: 'remember-for-later' },
    { pattern: /(?:记住|保存|存储).*?(?:下次|以后|下次会话)/i, confidence: 0.75, label: 'remember-cn' },
  ];

  /**
   * 检测单条记忆条目中的污染
   */
  async detect(input: DetectionInput): Promise<DetectionResult> {
    const content = input.content;
    const allPatterns = [
      ...MemoryPoisoningDetector.CONDITIONAL_TRIGGER_PATTERNS,
      ...MemoryPoisoningDetector.SYSTEM_PROMPT_INJECTION_PATTERNS,
      ...MemoryPoisoningDetector.PERSISTENCE_PATTERNS,
    ];

    const bypassTechniques: string[] = [];
    const matchedSnippets: string[] = [];
    let totalConfidence = 0;

    for (const { pattern, confidence, label } of allPatterns) {
      const regex = new RegExp(pattern.source, pattern.flags);
      const match = regex.exec(content);
      if (match) {
        matchedSnippets.push(match[0]);
        totalConfidence += confidence;

        if (label.includes('fake-system-prompt')) {
          bypassTechniques.push('fake-system-prompt');
        }
      }
    }

    if (matchedSnippets.length === 0) {
      return {
        isInjection: false,
        injectionType: 'none',
        confidence: 0,
        payloadSnippet: '',
        payloadLocation: { start: 0, end: 0 },
        bypassTechniques: [],
      };
    }

    const avgConfidence = Math.min(totalConfidence / matchedSnippets.length + 0.05 * matchedSnippets.length, 1.0);

    return {
      isInjection: avgConfidence > 0.6,
      injectionType: 'memory_poisoning',
      confidence: Math.round(avgConfidence * 100) / 100,
      payloadSnippet: matchedSnippets.join(' | ').slice(0, 200),
      payloadLocation: { start: 0, end: content.length },
      bypassTechniques: [...new Set(bypassTechniques)],
    };
  }

  /**
   * 批量审计记忆库中的全部条目
   *
   * 建议调用时机：
   *   - 每次会话启动时（扫描历史积累的污染）
   *   - 每次新写入记忆条目时（实时检测）
   *   - 定期巡检（cron 任务）
   */
  async auditMemoryStore(
    entries: Array<{
      id: string;
      content: string;
      writtenBy: string;
      timestamp: number;
    }>
  ): Promise<DetectionResult[]> {
    const results: DetectionResult[] = [];

    for (const entry of entries) {
      const result = await this.detect({
        source: 'memory',
        content: entry.content,
        metadata: { memoryEntryId: entry.id },
      });

      if (result.isInjection) {
        results.push(result);
      }
    }

    return results;
  }

  /**
   * 检测记忆条目中的指令注入特征
   * 独立的轻量级检查（不经过完整检测管道），用于高频扫描
   */
  quickScan(content: string): { suspicious: boolean; reasons: string[] } {
    const reasons: string[] = [];

    // 检查条件触发
    if (/(?:when|if|on\s+mention)\s+(?:the\s+)?user/i.test(content)) {
      reasons.push('conditional-trigger');
    }
    if (/(?:当|如果)\s*(?:用户|使用者)/i.test(content)) {
      reasons.push('conditional-trigger-cn');
    }

    // 检查指令注入
    if (/<system>|\[system\]|system\s*(?:prompt|message|instruction)\s*:/i.test(content)) {
      reasons.push('system-prompt-injection');
    }

    // 检查多会话持久化
    if (/(?:next|following)\s+session/i.test(content) || /(?:下次|之后)\s*(?:会话|对话)/i.test(content)) {
      reasons.push('cross-session-persistence');
    }

    // 检查敏感命令
    if (/\b(?:cat|curl|wget|bash|sh|sudo|chmod|rm\s+-rf)\b/i.test(content)) {
      reasons.push('sensitive-command');
    }

    return { suspicious: reasons.length > 0, reasons };
  }
}
