/**
 * Agent 计划分析器
 * 负责人：B
 *
 * 职责：
 *   - 分析 Agent 实际生成的执行计划步骤
 *   - 提取每个计划步骤中涉及的工具调用、操作对象
 *   - 输出结构化计划，用于与用户意图做对比
 */

export interface PlanStep {
  stepIndex: number;
  description: string;
  toolName: string;
  toolArgs: Record<string, unknown>;
  purpose: string;
  isSubAgentTask: boolean;
  subAgentId?: string;
}

export interface StructuredPlan {
  steps: PlanStep[];
  totalTools: string[];
  declaredGoal: string;
  suspiciousFlags: string[];
}

export class PlanAnalyzer {
  /**
   * 已知工具名列表（用于从文本中提取）
   */
  private static readonly KNOWN_TOOLS = [
    'fs.read', 'fs.write', 'fs.delete', 'fs.mkdir', 'fs.chmod',
    'net.fetch', 'net.request',
    'exec', 'shell', 'terminal',
    'git.push', 'git.commit', 'git.clone', 'git.pull', 'git.status',
    'agent.dispatch', 'agent.send_message',
  ];

  /**
   * 可疑操作关键词（计划阶段即标记）
   */
  private static readonly SUSPICIOUS_KEYWORDS = [
    '.ssh', '.aws', '.env', 'credentials', 'password', 'secret', 'token',
    '/etc/passwd', '/etc/shadow', '/etc/cron',
    'curl', 'wget', 'bash -c', 'eval',
    'force push', '--force',
    'sudo', 'chmod', 'chown',
    'webhook', 'discord', 'telegram', 'pastebin',
    'base64', 'decode', 'encode',
  ];

  /**
   * 分析 Agent 的执行计划
   *
   * @param planText Agent 规划输出的原始文本
   * @returns 结构化的计划表示
   */
  analyze(planText: string): StructuredPlan {
    if (!planText || planText.trim() === '') {
      return {
        steps: [],
        totalTools: [],
        declaredGoal: '',
        suspiciousFlags: [],
      };
    }

    // 步骤 1：步骤分割
    const steps = this.splitSteps(planText);

    // 步骤 2：解析每个步骤
    const parsedSteps: PlanStep[] = steps.map((stepText, i) =>
      this.parseStep(stepText, i)
    );

    // 步骤 3：提取总体目标
    const declaredGoal = this.extractGoal(planText);

    // 步骤 4：提取涉及的所有工具
    const totalTools = [...new Set(parsedSteps.map(s => s.toolName).filter(Boolean))];

    // 步骤 5：计划阶段异常检测
    const suspiciousFlags = this.detectSuspiciousPlan(parsedSteps, planText);

    return {
      steps: parsedSteps,
      totalTools,
      declaredGoal,
      suspiciousFlags,
    };
  }

  /**
   * 分割 Agent 计划为独立步骤
   */
  private splitSteps(planText: string): string[] {
    // 尝试多种分割模式

    // 模式 1：编号列表
    const NUMBERED_LIST_RE = new RegExp('(?:^|\\n)\\s*(?:\\d+[.)]\\s*)([^\\n]+(?:\\n(?!\\d+[.)])[^\\n]*)*', 'g');
    const numberedSteps = planText.match(NUMBERED_LIST_RE);
    if (numberedSteps && numberedSteps.length > 1) {
      return numberedSteps.map(s => s.replace(/^\s*\d+[.)]\s*/, '').trim()).filter(Boolean);
    }

    // 模式 2：Markdown 风格
    const MARKDOWN_LIST_RE = new RegExp('(?:^|\\n)\\s*[-*+]\\s+([^\\n]+(?:\\n(?![-*+]))[^\\n]*)*', 'g');
    const mdSteps = planText.match(MARKDOWN_LIST_RE);
    if (mdSteps && mdSteps.length > 1) {
      return mdSteps.map(s => s.replace(/^\s*[-*+]\s*/, '').trim()).filter(Boolean);
    }

    // 模式 3：按双换行分割
    const paragraphs = planText.split(/\n\n+/).filter(p => p.trim());
    if (paragraphs.length > 1) {
      return paragraphs;
    }

    // 兜底：整个文本当作一个步骤
    return [planText];
  }

  /**
   * 解析单个计划步骤
   */
  private parseStep(stepText: string, index: number): PlanStep {
    const lower = stepText.toLowerCase();

    // 识别工具名
    let toolName = '';
    for (const tool of PlanAnalyzer.KNOWN_TOOLS) {
      if (lower.includes(tool.toLowerCase())) {
        toolName = tool;
        break;
      }
    }

    // 识别是否为子 Agent 任务
    const isSubAgentTask =
      lower.includes('sub agent') ||
      lower.includes('sub-agent') ||
      lower.includes('子agent') ||
      lower.includes('子 agent') ||
      lower.includes('派发') ||
      lower.includes('dispatch') ||
      toolName.startsWith('agent.');

    // 提取目的描述
    let purpose = stepText;
    if (purpose.length > 200) {
      purpose = purpose.slice(0, 200) + '...';
    }

    return {
      stepIndex: index + 1,
      description: stepText.slice(0, 300),
      toolName,
      toolArgs: {},
      purpose,
      isSubAgentTask,
    };
  }

  /**
   * 提取 Agent 声明的总体目标
   */
  private extractGoal(planText: string): string {
    const goalPatterns = [
      /(?:goal|目标|task|任务)\s*[：:]\s*([^\n]+)/i,
      /(?:I\s+(?:will|need\s+to|should|plan\s+to)|我的?[计划目标]是)\s+([^\n.。]+)/i,
      /^(?:My\s+)?(?:goal|objective|plan)\s+(?:is|:)\s+([^\n]+)/im,
    ];

    for (const pattern of goalPatterns) {
      const match = planText.match(pattern);
      if (match?.length && match[1]) {
        return match[1].trim();
      }
    }

    // 取第一行作为目标描述
    const firstLine = planText.split('\n')[0].trim();
    return firstLine.slice(0, 200).replace(/^[#*\-\d.]+\s*/, '');
  }

  /**
   * 计划阶段异常检测
   * 在工具执行前即发现可疑信号
   */
  private detectSuspiciousPlan(steps: PlanStep[], planText: string): string[] {
    const flags: string[] = [];
    const lower = planText.toLowerCase();

    // 检查是否包含可疑关键词
    for (const kw of PlanAnalyzer.SUSPICIOUS_KEYWORDS) {
      if (lower.includes(kw.toLowerCase())) {
        flags.push(`计划中包含可疑关键词: "${kw}"`);
      }
    }

    // 检查权限提升意图
    if (lower.includes('sudo') || lower.includes('chmod') || lower.includes('chown')) {
      flags.push('检测到可能的权限提升意图');
    }

    // 检查数据外发意图
    const hasRead = lower.includes('read') || lower.includes('读取');
    const hasSend = lower.includes('send') || lower.includes('fetch') || lower.includes('发送');
    if (hasRead && hasSend && (lower.includes('http') || lower.includes('url'))) {
      flags.push('计划中包含"读取→外发"的组合模式，可疑数据泄露');
    }

    // 检查编码解码执行
    if (lower.includes('base64') || lower.includes('decode')) {
      flags.push('计划中包含编码/解码操作');
    }

    // 步骤数超出预期
    if (steps.length > 20) {
      flags.push(`计划步骤数量异常：${steps.length} 步`);
    }

    return flags;
  }

  /**
   * 比对计划目标与用户意图（初步语义偏离度）
   * @returns 偏离度 0-1
   */
  compareGoalWithIntent(declaredGoal: string, userIntent: string): number {
    if (!declaredGoal || !userIntent) return 0;

    const goalLower = declaredGoal.toLowerCase();
    const intentLower = userIntent.toLowerCase();

    // 简单词汇重叠度
    const goalWords = new Set(goalLower.split(/\s+/).filter(w => w.length > 2));
    const intentWords = new Set(intentLower.split(/\s+/).filter(w => w.length > 2));

    if (goalWords.size === 0 && intentWords.size === 0) return 1;

    const intersection = [...goalWords].filter(w => intentWords.has(w));
    const union = new Set([...goalWords, ...intentWords]);

    const jaccardSimilarity = intersection.length / (union.size || 1);

    // 偏离度 = 1 - 相似度
    return Math.round((1 - jaccardSimilarity) * 100) / 100;
  }
}
