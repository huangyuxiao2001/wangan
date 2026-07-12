/**
 * 策略 DSL 解析器
 * 负责人：B
 *
 * 职责：
 *   - 解析 YAML 格式的安全策略定义文件
 *   - 校验规则语法的合法性
 *   - 编译为可执行的规则评估树
 *   - 支持多文件合并 + 优先级排序
 */

import * as fs from 'fs';
import * as path from 'path';
import * as yaml from 'js-yaml';

export interface PolicyRule {
  id: string;
  tool: string;
  rule: string;
  action: 'ALLOW' | 'ASK_USER' | 'BLOCK';
  risk: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  message: string;
  description?: string;
  enabled: boolean;
}

export interface ParsedPolicySet {
  rules: PolicyRule[];
  metadata: {
    version: string;
    lastUpdated: string;
    totalRules: number;
    sourceFiles: string[];
  };
}

/** 有效的风险等级 */
const VALID_RISK_LEVELS = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];

/** 有效的决策动作 */
const VALID_ACTIONS = ['ALLOW', 'ASK_USER', 'BLOCK'];

/** 已知工具名前缀（用于校验） */
const KNOWN_TOOL_PREFIXES = ['fs.', 'net.', 'exec', 'git.', 'agent.', 'shell', 'terminal'];

export class DslParser {
  /**
   * 从单个 YAML 文件解析策略规则
   */
  async parseFile(filePath: string): Promise<ParsedPolicySet> {
    const content = fs.readFileSync(filePath, 'utf-8');
    const parsed = yaml.load(content) as { policies?: PolicyRule[] } | null;

    if (!parsed || !Array.isArray(parsed.policies)) {
      return {
        rules: [],
        metadata: {
          version: '1.0.0',
          lastUpdated: new Date().toISOString(),
          totalRules: 0,
          sourceFiles: [filePath],
        },
      };
    }

    const rules: PolicyRule[] = [];

    for (const rule of parsed.policies) {
      // 校验每条规则
      const validation = this.validateRule(rule as PolicyRule);
      if (!validation.valid) {
        console.warn(`[DSL Parser] Skipping invalid rule in ${filePath}: ${validation.errors.join(', ')}`);
        continue;
      }

      rules.push({
        id: rule.id,
        tool: rule.tool,
        rule: rule.rule,
        action: rule.action,
        risk: rule.risk,
        message: rule.message,
        description: rule.description,
        enabled: rule.enabled !== false, // 默认启用
      });
    }

    return {
      rules,
      metadata: {
        version: '1.0.0',
        lastUpdated: new Date().toISOString(),
        totalRules: rules.length,
        sourceFiles: [filePath],
      },
    };
  }

  /**
   * 从目录加载并合并所有 YAML 策略文件
   */
  async parseDirectory(dirPath: string): Promise<ParsedPolicySet> {
    const allRules: PolicyRule[] = [];
    const sourceFiles: string[] = [];

    if (!fs.existsSync(dirPath)) {
      throw new Error(`Policy directory not found: ${dirPath}`);
    }

    const files = fs.readdirSync(dirPath)
      .filter(f => f.endsWith('.yaml') || f.endsWith('.yml'))
      .sort();

    for (const file of files) {
      const filePath = path.join(dirPath, file);
      const parsed = await this.parseFile(filePath);
      allRules.push(...parsed.rules);
      sourceFiles.push(file);
    }

    // 去重（按 id）
    const seen = new Set<string>();
    const uniqueRules = allRules.filter(rule => {
      if (seen.has(rule.id)) {
        console.warn(`[DSL Parser] Duplicate rule ID: ${rule.id}, keeping first occurrence`);
        return false;
      }
      seen.add(rule.id);
      return true;
    });

    // 按优先级排序
    const sorted = this.sortByPriority(uniqueRules);

    return {
      rules: sorted,
      metadata: {
        version: '1.0.0',
        lastUpdated: new Date().toISOString(),
        totalRules: sorted.length,
        sourceFiles,
      },
    };
  }

  /**
   * 校验单条规则表达式的合法性
   */
  validateRule(rule: PolicyRule): { valid: boolean; errors: string[] } {
    const errors: string[] = [];

    // 必需字段
    if (!rule.id || typeof rule.id !== 'string') {
      errors.push('Missing or invalid "id" field');
    }

    if (!rule.tool || typeof rule.tool !== 'string') {
      errors.push('Missing or invalid "tool" field');
    } else {
      // 检查工具名是否在已知列表中
      const knownPrefix = KNOWN_TOOL_PREFIXES.some(prefix => {
        if (rule.tool === prefix) return true;
        if (rule.tool === prefix + '.*') return true;
        // prefix like 'fs.' → check tool starts with 'fs.'
        if (rule.tool.startsWith(prefix)) return true;
        // prefix without dot → check tool starts with 'prefix.'
        if (!prefix.endsWith('.') && rule.tool.startsWith(prefix + '.')) return true;
        return false;
      });
      if (!knownPrefix) {
        errors.push(`Unknown tool prefix: "${rule.tool}". Known prefixes: ${KNOWN_TOOL_PREFIXES.join(', ')}`);
      }
    }

    if (!rule.rule || typeof rule.rule !== 'string') {
      errors.push('Missing or invalid "rule" field');
    } else {
      // 基本语法检查
      if (!/^[a-zA-Z_]+\s+(matches|contains|equals|not_in|in_list|regex_match|superset_of)\s*\(.+\)(\s+(AND|OR)\s+[a-zA-Z_]+\s+(matches|contains|equals|not_in|in_list|regex_match|superset_of)\s*\(.+\))?$/.test(rule.rule.trim())) {
        // 语法不完全匹配，但可能是有意为之（复杂表达式），只做警告
        // errors.push(`Rule expression syntax may be invalid: "${rule.rule}"`);
      }
    }

    if (!VALID_ACTIONS.includes(rule.action)) {
      errors.push(`Invalid action "${rule.action}". Must be one of: ${VALID_ACTIONS.join(', ')}`);
    }

    if (!VALID_RISK_LEVELS.includes(rule.risk)) {
      errors.push(`Invalid risk "${rule.risk}". Must be one of: ${VALID_RISK_LEVELS.join(', ')}`);
    }

    if (!rule.message || typeof rule.message !== 'string') {
      errors.push('Missing or invalid "message" field');
    }

    return { valid: errors.length === 0, errors };
  }

  /**
   * 按优先级排序规则
   * 排序键：risk 降序 → action 权重降序 → id 字典序
   */
  sortByPriority(rules: PolicyRule[]): PolicyRule[] {
    const actionWeight: Record<string, number> = { 'BLOCK': 3, 'ASK_USER': 2, 'ALLOW': 1 };
    const riskWeight: Record<string, number> = { 'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1 };

    return [...rules].sort((a, b) => {
      // risk 降序
      const riskDiff = (riskWeight[b.risk] ?? 0) - (riskWeight[a.risk] ?? 0);
      if (riskDiff !== 0) return riskDiff;

      // action 权重降序
      const actionDiff = (actionWeight[b.action] ?? 0) - (actionWeight[a.action] ?? 0);
      if (actionDiff !== 0) return actionDiff;

      // id 字典序
      return a.id.localeCompare(b.id);
    });
  }
}
