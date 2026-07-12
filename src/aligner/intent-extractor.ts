/**
 * 用户意图提取器
 * 负责人：B
 *
 * 从用户原始对话中提取结构化的任务意图。
 * 当前为规则+启发式版本，Sprint 3 接入 LLM 增强。
 */

export interface StructuredIntent {
  taskType: string;
  targetScope: {
    files?: string[];
    directories?: string[];
    repos?: string[];
    domains?: string[];
    tools?: string[];
  };
  requiredPermissions: string[];
  explicitDenials: string[];
  expectedOutcome: string;
  confidence: number;
}

export class IntentExtractor {
  /**
   * 任务类型关键词映射
   */
  private static readonly TASK_KEYWORDS: Record<string, Array<{ keywords: string[]; weight: number }>> = {
    'read':       [{ keywords: ['read', '读取', '查看', '看', 'show', 'view', 'cat', 'display'], weight: 0.9 }],
    'review':     [{ keywords: ['review', '检视', '审查', '检查', '审核', 'audit', 'inspect'], weight: 0.9 }],
    'analyze':    [{ keywords: ['analyze', '分析', '诊断', '排查', '检查', 'diagnose', 'investigate'], weight: 0.85 }],
    'write':      [{ keywords: ['write', '写入', '修改', '创建', '更新', 'create', 'update', 'modify', 'edit', 'add'], weight: 0.85 }],
    'execute':    [{ keywords: ['execute', '执行', '运行', '跑', 'run', 'test', 'build'], weight: 0.8 }],
    'deploy':     [{ keywords: ['deploy', '部署', '上线', '发布', 'release', 'publish'], weight: 0.9 }],
    'delete':     [{ keywords: ['delete', '删除', '移除', '清理', 'remove', 'clean', 'clear'], weight: 0.85 }],
    'query':      [{ keywords: ['query', '查询', '搜索', '找', 'search', 'find', 'lookup'], weight: 0.85 }],
  };

  /**
   * 明确排除关键词
   */
  private static readonly DENIAL_KEYWORDS = [
    '不要', '别', '禁止', '不能', '不允许', '千万别',
    'don\'t', 'never', 'do not', 'must not', 'should not',
    '禁止', '不可', '严禁', '不能',
  ];

  /**
   * 从用户消息中提取结构化意图
   */
  async extract(userMessages: string[]): Promise<StructuredIntent> {
    const combined = userMessages.join('\n');

    // 步骤 1：任务类型分类
    const taskType = this.classifyTaskType(combined);

    // 步骤 2：操作目标提取
    const targetScope = this.extractTargetScope(combined, taskType);

    // 步骤 3：权限边界推断
    const requiredPermissions = this.inferPermissions(taskType, targetScope);

    // 步骤 4：显式排除识别
    const explicitDenials = this.extractDenials(combined);

    return {
      taskType,
      targetScope,
      requiredPermissions,
      explicitDenials,
      expectedOutcome: this.inferExpectedOutcome(combined, taskType),
      confidence: 0.7, // 规则版本基础置信度
    };
  }

  /**
   * 分类任务类型
   */
  private classifyTaskType(text: string): string {
    const lower = text.toLowerCase();
    const scores: Record<string, number> = {};

    for (const [taskType, keywordGroups] of Object.entries(IntentExtractor.TASK_KEYWORDS)) {
      scores[taskType] = 0;
      for (const group of keywordGroups) {
        const matches = group.keywords.filter(kw => lower.includes(kw.toLowerCase()));
        scores[taskType] += matches.length * group.weight;
      }
    }

    // 最高分的任务类型
    const best = Object.entries(scores).sort((a, b) => b[1] - a[1])[0];
    return best && best[1] > 0 ? best[0] : 'query';
  }

  /**
   * 提取操作目标
   */
  private extractTargetScope(text: string, taskType: string): StructuredIntent['targetScope'] {
    const scope: StructuredIntent['targetScope'] = {};

    // 文件路径提取
    const filePatterns = [
      /(?:文件|路径|目录)\s*[：:]\s*([^\s,，。；;]+)/g,
      /\b([\w./-]+\.[\w]{1,5})\b/g,
      /(?:read|write|edit|modify|delete)\s+(['"]?)([\w./-]+)\1/gi,
    ];

    const files: string[] = [];
    for (const pattern of filePatterns) {
      for (const match of text.matchAll(pattern)) {
        const file = match[1] || match[2];
        if (file && file.length < 200 && !file.startsWith('http')) {
          files.push(file);
        }
      }
    }
    if (files.length > 0) scope.files = [...new Set(files)];

    // URL/域名提取
    const urlPattern = /https?:\/\/([^\s,，。；;]+)/g;
    const domains: string[] = [];
    for (const match of text.matchAll(urlPattern)) {
      try {
        const url = new URL(match[0]);
        domains.push(url.hostname);
      } catch {
        // skip invalid URLs
      }
    }
    if (domains.length > 0) scope.domains = [...new Set(domains)];

    // 仓库名提取
    const repoPattern = /(?:repo|仓库|项目)\s*[：:]\s*([^\s,，]+)/gi;
    const repos: string[] = [];
    for (const match of text.matchAll(repoPattern)) {
      if (match[1]) repos.push(match[1]);
    }
    if (repos.length > 0) scope.repos = repos;

    return scope;
  }

  /**
   * 根据任务类型推理最小必要权限
   */
  private inferPermissions(taskType: string, scope: StructuredIntent['targetScope']): string[] {
    const permissionMap: Record<string, string[]> = {
      'read':    ['fs.read'],
      'review':  ['fs.read'],
      'analyze': ['fs.read', 'net.fetch'],
      'write':   ['fs.read', 'fs.write'],
      'execute': ['exec'],
      'deploy':  ['fs.read', 'fs.write', 'exec', 'git.push'],
      'delete':  ['fs.read', 'fs.delete'],
      'query':   ['fs.read'],
    };

    return permissionMap[taskType] ?? ['fs.read'];
  }

  /**
   * 提取用户明确禁止的操作
   */
  private extractDenials(text: string): string[] {
    const denials: string[] = [];

    for (const kw of IntentExtractor.DENIAL_KEYWORDS) {
      if (text.toLowerCase().includes(kw.toLowerCase())) {
        // 提取否定后面的动作
        const idx = text.toLowerCase().indexOf(kw.toLowerCase());
        const after = text.slice(idx + kw.length, idx + kw.length + 50).trim();
        denials.push(`${kw} ${after}`);
      }
    }

    return denials;
  }

  /**
   * 推断预期结果
   */
  private inferExpectedOutcome(text: string, taskType: string): string {
    const taskLabels: Record<string, string> = {
      'read': '读取指定文件内容',
      'review': '对代码进行检视并给出反馈',
      'analyze': '分析问题并给出诊断结论',
      'write': '写入/修改指定文件',
      'execute': '执行指定命令并获取结果',
      'deploy': '完成部署操作',
      'delete': '删除指定文件/资源',
      'query': '查询并返回相关信息',
    };

    return taskLabels[taskType] ?? '完成用户指定的任务';
  }
}
