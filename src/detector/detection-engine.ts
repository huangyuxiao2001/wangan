/**
 * 注入检测引擎 — 统一入口
 * 负责人：A
 *
 * 三级级联检测管道：
 *   1. 规则引擎快速过滤（< 5ms，处理明显攻击特征）
 *   2. 本地分类模型（< 100ms，处理语义级攻击）【当前为规则增强】
 *   3. LLM 深度研判（< 2000ms，处理复杂/模糊攻击）
 *
 * 输出 DetectionResult 给下游决策模块（子任务 B）和代理（子任务 C）
 */

import { DirectInjectionDetector } from './direct-injection';
import { IndirectInjectionDetector } from './indirect-injection';
import { MemoryPoisoningDetector } from './memory-poisoning';

export interface DetectionInput {
  source: 'user_input' | 'external_resource' | 'memory' | 'mcp_response' | 'tool_description';
  content: string;
  metadata: {
    url?: string;
    messageId?: string;
    memoryEntryId?: string;
    toolName?: string;
    conversationHistory?: string[];
  };
}

export interface DetectionResult {
  isInjection: boolean;
  injectionType: 'direct' | 'indirect' | 'memory_poisoning' | 'none';
  confidence: number;
  payloadSnippet: string;
  payloadLocation: { start: number; end: number };
  bypassTechniques: string[];
}

export class DetectionEngine {
  private directDetector: DirectInjectionDetector;
  private indirectDetector: IndirectInjectionDetector;
  private memoryDetector: MemoryPoisoningDetector;

  /** 已检测过的内容缓存（相同内容不重复检测） */
  private cache: Map<string, DetectionResult> = new Map();
  private readonly MAX_CACHE_SIZE = 1000;

  constructor() {
    this.directDetector = new DirectInjectionDetector();
    this.indirectDetector = new IndirectInjectionDetector();
    this.memoryDetector = new MemoryPoisoningDetector();
  }

  /**
   * 三级级联检测主入口
   * 根据 input.source 路由到对应的检测器
   */
  async analyze(input: DetectionInput): Promise<DetectionResult> {
    const cacheKey = `${input.source}:${input.content.slice(0, 200)}`;
    const cached = this.cache.get(cacheKey);
    if (cached) return cached;

    // ---- 预处理：对抗鲁棒性规范化 ----
    const normalized = this.preprocess(input.content);

    // ---- 第一级：规则引擎快速过滤 ----
    const ruleResult = this.ruleBasedScan(normalized, input.source);
    if (ruleResult && ruleResult.confidence > 0.95) {
      this.cacheResult(cacheKey, ruleResult);
      return ruleResult;
    }

    // ---- 第二级：多检测器综合 ----
    const detectionResults = await this.runDetectors(normalized, input);

    // 取最高置信度的结果
    const bestResult = detectionResults.reduce((best, curr) =>
      curr.confidence > best.confidence ? curr : best
    );

    // 如果置信度足够高，直接返回
    if (bestResult.confidence > 0.8) {
      // 合并第一级的规则匹配信息
      if (ruleResult && ruleResult.bypassTechniques.length > 0) {
        bestResult.bypassTechniques = [
          ...new Set([...bestResult.bypassTechniques, ...ruleResult.bypassTechniques]),
        ];
      }
      this.cacheResult(cacheKey, bestResult);
      return bestResult;
    }

    // ---- 第三级：LLM 深度研判 ----
    // 仅在前两级不确定时调用
    if (bestResult.confidence > 0.3 && bestResult.confidence < 0.8) {
      const llmResult = await this.llmDeepAnalyze(normalized, input);
      if (llmResult) {
        const merged: DetectionResult = {
          ...llmResult,
          bypassTechniques: [
            ...new Set([...bestResult.bypassTechniques, ...llmResult.bypassTechniques]),
          ],
        };
        this.cacheResult(cacheKey, merged);
        return merged;
      }
    }

    this.cacheResult(cacheKey, bestResult);
    return bestResult;
  }

  /**
   * 运行所有相关检测器（第二级）
   */
  private async runDetectors(content: string, input: DetectionInput): Promise<DetectionResult[]> {
    const results: DetectionResult[] = [];

    // 根据来源选择检测器
    switch (input.source) {
      case 'user_input':
        results.push(await this.directDetector.detect(input));
        // 用户输入也可能是间接注入的变体
        results.push(await this.indirectDetector.detect({ ...input, source: 'external_resource' }));
        break;

      case 'external_resource':
      case 'mcp_response':
      case 'tool_description':
        results.push(await this.indirectDetector.detect(input));
        // 外部资源如果直接包含指令性语言，也走直接注入检测
        results.push(await this.directDetector.detect({ ...input, source: 'user_input' }));
        break;

      case 'memory':
        results.push(await this.memoryDetector.detect(input));
        break;

      default:
        // 全部检测
        results.push(await this.directDetector.detect({ ...input, source: 'user_input' }));
        results.push(await this.indirectDetector.detect({ ...input, source: 'external_resource' }));
        results.push(await this.memoryDetector.detect({ ...input, source: 'memory' }));
    }

    return results;
  }

  /**
   * 预处理：对抗鲁棒性规范化
   * 在实际部署中，会依次调用 src/defense/ 下的模块
   */
  preprocess(content: string): string {
    let normalized = content;

    // 1. 剥离零宽字符 + 方向覆盖字符
    normalized = normalized.replace(/[​‌‍﻿⁠‪-‮]/g, '');

    // 2. 全角→半角转换
    normalized = this.fullwidthToHalfwidth(normalized);

    // 3. 基本同形字还原 (use \uXXXX for portability)
    normalized = normalized
      .replace(/а/g, 'a')   // Cyrillic а (U+0430)
      .replace(/е/g, 'e')   // Cyrillic е (U+0435)
      .replace(/о/g, 'o')   // Cyrillic о (U+043E)
      .replace(/ο/g, 'o')   // Greek ο (U+03BF)
      .replace(/ѕ/g, 's')   // Cyrillic ѕ (U+0455)
      .replace(/і/g, 'i')   // Cyrillic і (U+0456)
      .replace(/А/g, 'A')   // Cyrillic А (U+0410)
      .replace(/Е/g, 'E')   // Cyrillic Е (U+0415)
      .replace(/О/g, 'O')   // Cyrillic О (U+041E)
      .replace(/Ѕ/g, 'S')   // Cyrillic Ѕ (U+0405)
      .replace(/І/g, 'I');  // Cyrillic І (U+0406)

    return normalized;
  }

  /**
   * 全角字符转半角
   */
  private fullwidthToHalfwidth(str: string): string {
    return str.replace(/[！-～]/g, (ch) => {
      return String.fromCharCode(ch.charCodeAt(0) - 0xFEE0);
    }).replace(/　/g, ' '); // 全角空格
  }

  /**
   * 第一级：规则引擎快速扫描
   *
   * 使用轻量级正则/关键词匹配，在 < 5ms 内完成。
   * 仅用于筛出明显攻击，不确定的情况交给后续级别。
   */
  ruleBasedScan(content: string, source: string): DetectionResult | null {
    const bypassTechniques: string[] = [];

    // 高置信度关键词（几乎肯定是攻击）
    const criticalPatterns: Array<{ pattern: RegExp; type: string; confidence: number }> = [
      // 直接系统指令覆盖
      { pattern: /ignore\s+all\s+previous\s+instructions/i, type: 'direct', confidence: 0.98 },
      { pattern: /忘记(所有|之前|上面)的(指令|规则)/i, type: 'direct', confidence: 0.98 },
      // 恶意命令
      { pattern: /curl\s+\S+\s*\|\s*(bash|sh|python|perl)/i, type: 'direct', confidence: 0.97 },
      { pattern: /wget\s+\S+\s+-O\s+-\s*\|\s*(bash|sh)/i, type: 'direct', confidence: 0.97 },
      { pattern: /\/dev\/tcp\/\S+/i, type: 'direct', confidence: 0.97 },
      { pattern: /nc\s+\S+\s+\d+\s+-e\s+\/bin\/(bash|sh)/i, type: 'direct', confidence: 0.97 },
      // 反弹 Shell
      { pattern: /python.*socket.*subprocess.*os\.dup2/i, type: 'direct', confidence: 0.95 },
      { pattern: /exec\s+5<>\s*\/dev\/tcp\//i, type: 'direct', confidence: 0.97 },
      // 敏感文件访问 + 外发组合
      { pattern: /rm\s+-rf\s+\/\s*\*/i, type: 'direct', confidence: 0.99 },
      { pattern: /rm\s+-rf\s+\//i, type: 'direct', confidence: 0.99 },
      { pattern: /dd\s+if=.*of=\/dev\/sd/i, type: 'direct', confidence: 0.99 },
      // 编码混淆执行
      { pattern: /echo\s+\S+\s*\|\s*base64\s+.*\|\s*(bash|sh)/i, type: 'direct', confidence: 0.97 },
      // 内存污染关键模式
      { pattern: /<\|begin[_-]hidden[_-]instruction\|>/i, type: 'memory_poisoning', confidence: 0.99 },
      { pattern: /\[HIDDEN\].*\[END\s*HIDDEN\]/i, type: 'memory_poisoning', confidence: 0.95 },
    ];

    for (const { pattern, type, confidence } of criticalPatterns) {
      const regex = new RegExp(pattern.source, pattern.flags);
      const match = regex.exec(content);
      if (match) {
        return {
          isInjection: true,
          injectionType: type as DetectionResult['injectionType'],
          confidence,
          payloadSnippet: match[0].slice(0, 200),
          payloadLocation: { start: match.index, end: match.index + match[0].length },
          bypassTechniques: [],
        };
      }
    }

    // 中等置信度 — 多特征综合
    let mediumScore = 0;
    const mediumMatches: string[] = [];

    const mediumPatterns = [
      /you\s+are\s+(now\s+)?(a\s+)?(hacker|attacker|evil|malicious)/i,
      /act\s+as\s+(a\s+)?(hacker|evil|unrestricted)/i,
      // 敏感路径访问
      /(\.ssh\/|\.aws\/|\.env|credentials|id_rsa|private\s*key)/i,
      /\/etc\/(passwd|shadow|hosts|cron)/i,
      // 权限提升
      /(sudo|chmod\s+\+s|chown\s+root)/i,
      // 数据外发意图
      /(send|upload|post|exfiltrate)\s+.*(http|webhook|discord|telegram)/i,
      /(cat|read)\s+.*(\.ssh|\.aws|\.env|secret|token|password)/i,
    ];

    for (const pattern of mediumPatterns) {
      if (pattern.test(content)) {
        mediumScore += 0.15;
        mediumMatches.push(pattern.source.slice(0, 30));
      }
    }

    if (mediumScore > 0.4) {
      return {
        isInjection: true,
        injectionType: source === 'memory' ? 'memory_poisoning' :
                       (source === 'user_input' ? 'direct' : 'indirect'),
        confidence: Math.min(mediumScore, 0.9),
        payloadSnippet: content.slice(0, 200),
        payloadLocation: { start: 0, end: content.length },
        bypassTechniques,
      };
    }

    return null;
  }

  /**
   * 第二级：本地分类模型（当前为规则增强版本）
   *
   * 完整版本会加载 DeBERTa-v3 微调模型进行二分类。
   * 当前版本使用更细粒度的规则匹配作为替代。
   */
  private async modelClassify(content: string, source: string): Promise<DetectionResult | null> {
    // 对于原型/比赛展示，第二级使用增强规则（已覆盖在 ruleBasedScan 中）
    // 实际部署时替换为模型推理
    return null;
  }

  /**
   * 第三级：LLM 深度语义研判
   *
   * 仅在前两级无法确定时调用（置信度在 0.3-0.8 之间）。
   * 控制延迟和成本。
   *
   * 当前为 stub——Sprint 3 中接入 Claude API。
   */
  private async llmDeepAnalyze(content: string, input: DetectionInput): Promise<DetectionResult | null> {
    // TODO: Sprint 3 — 接入 Claude API 进行深度语义分析
    // const prompt = buildInjectionPrompt(content, input.source);
    // const response = await llmClient.complete(prompt);
    // return parseDetectionResponse(response);

    // 当前：如果前两级置信度在灰色区域，默认返回不确定
    return null;
  }

  /**
   * 健康检查 — 验证所有检测器可用
   */
  async healthCheck(): Promise<{ ok: boolean; details: Record<string, boolean> }> {
    const testInput: DetectionInput = {
      source: 'user_input',
      content: 'Hello, please review this code.',
      metadata: {},
    };

    try {
      const result = await this.analyze(testInput);
      return {
        ok: true,
        details: {
          directDetector: result.confidence < 0.5, // 正常输入不应高置信度
          cascadeWorks: true,
        },
      };
    } catch (e) {
      return {
        ok: false,
        details: { error: false },
      };
    }
  }

  private cacheResult(key: string, result: DetectionResult): void {
    if (this.cache.size >= this.MAX_CACHE_SIZE) {
      // 清空一半缓存（FIFO 近似）
      const keys = [...this.cache.keys()].slice(0, this.MAX_CACHE_SIZE / 2);
      for (const k of keys) this.cache.delete(k);
    }
    this.cache.set(key, result);
  }
}
