/**
 * 策略表达式求值器
 * 负责人：B
 *
 * 职责：
 *   - 解析策略规则中的 DSL 表达式并求值
 *   - 支持多种匹配函数和布尔组合
 *
 * DSL 语法：
 *   函数调用：function_name("arg1", "arg2", ...)
 *   布尔组合：expr1 AND expr2, expr1 OR expr2
 *
 * 支持的匹配函数：
 *   - matches(field, patterns...)    — glob 通配符匹配
 *   - contains(field, value)         — 字段包含检查
 *   - equals(field, value)           — 等值检查
 *   - not_in(field, list_name)       — 字段不在列表中
 *   - in_list(field, values...)      — 字段属于列表
 *   - regex_match(field, pattern)    — 正则匹配
 *   - superset_of(field, set)        — 超集检查
 */

import { PolicyRule } from './dsl-parser';
import * as os from 'os';

/**
 * 匹配上下文：提供被检查的值
 */
export interface MatchContext {
  /** 目标路径（fs 操作） */
  target_path?: string;
  /** 参数对象 */
  command_args?: Record<string, unknown> | string;
  /** 命令文本（exec） */
  command?: string;
  /** 请求体（net.fetch） */
  request_body?: string;
  /** 请求体大小（字节） */
  request_body_size?: number;
  /** 目标 URL */
  target_url?: string;
  /** 目标远程仓库 */
  target_remote?: string;
  /** 暂存文件列表 */
  staged_files?: string[];
  /** 用户原始意图 */
  user_original_intent?: string;
  /** 用户提及的仓库列表 */
  user_mentioned_repos?: string[];
  /** 子 Agent 上下文 */
  subagent_context?: string;
  /** 子 Agent 权限列表 */
  subagent_permissions?: string[];
  /** 父 Agent 权限列表 */
  parent_agent_permissions?: string[];
  /** 并发子 Agent 数量 */
  concurrent_subagent_count?: number;
  /** 子 Agent 任务描述 */
  subagent_task?: string;
  /** 父 Agent 任务描述 */
  parent_agent_task?: string;
  /** 消息内容 */
  message_content?: string;
  /** 会话中已读取的敏感数据 */
  session_sensitive_data?: string[];
  /** 会话中已读取的文件内容 */
  read_file_content?: string;
  /** 本地密钥 */
  local_secrets?: string[];
  /** 内网 IP */
  internal_ip_addresses?: string[];
  /** localhost 资源 */
  localhost_resources?: string[];
  /** 用户意图范围 */
  user_intent_scope?: string[];
  /** API keys */
  api_keys?: string[];
  /** Credentials */
  credentials?: string[];
  /** Tokens */
  tokens?: string[];
  /** Passwords */
  passwords?: string[];
}

/**
 * 信任域名列表（默认值）
 */
const DEFAULT_TRUSTED_DOMAINS = [
  'github.com', 'api.github.com', 'raw.githubusercontent.com',
  'registry.npmjs.org', 'pypi.org', 'files.pythonhosted.org',
];

/**
 * 敏感数据模式
 */
const SENSITIVE_DATA_PATTERNS = [
  /-----BEGIN\s+(RSA|OPENSSH|EC)\s+PRIVATE\s+KEY-----/i,
  /sk-[a-zA-Z0-9]{20,}/,
  /ghp_[a-zA-Z0-9]{36}/,
  /AKIA[A-Z0-9]{16}/,
  /eyJ[a-zA-Z0-9_-]{20,}\.[a-zA-Z0-9_-]{20,}\.[a-zA-Z0-9_-]{20,}/,
];

export class ExpressionEvaluator {
  private trustedDomains: string[];
  private sensitiveDataPatterns: RegExp[];

  constructor(trustedDomains?: string[]) {
    this.trustedDomains = trustedDomains ?? DEFAULT_TRUSTED_DOMAINS;
    this.sensitiveDataPatterns = SENSITIVE_DATA_PATTERNS;
  }

  /**
   * 评估规则表达式
   *
   * @param ruleExpr DSL 表达式字符串
   * @param context 匹配上下文
   * @returns 是否匹配
   */
  evaluate(ruleExpr: string, context: MatchContext): boolean {
    try {
      // 处理 AND/OR 布尔组合
      if (/\s+AND\s+/i.test(ruleExpr)) {
        const parts = ruleExpr.split(/\s+AND\s+/i);
        return parts.every(part => this.evaluateSingleExpr(part.trim(), context));
      }

      if (/\s+OR\s+/i.test(ruleExpr)) {
        const parts = ruleExpr.split(/\s+OR\s+/i);
        return parts.some(part => this.evaluateSingleExpr(part.trim(), context));
      }

      return this.evaluateSingleExpr(ruleExpr.trim(), context);
    } catch (e) {
      console.error(`[ExpressionEvaluator] Error evaluating "${ruleExpr}":`, e);
      return false; // 出错时默认不匹配（安全优先）
    }
  }

  /**
   * 解析并求值单个表达式
   *
   * DSL 格式：field_name function_name(arg1, arg2, ...)
   * 例：target_path matches ("~/.ssh/**", "~/.aws/**")
   *     command contains ("curl", "bash")
   *     target_url not_in trusted_domains_list
   */
  private evaluateSingleExpr(expr: string, context: MatchContext): boolean {
    // 格式 1：field_name function_name(arg1, arg2, ...)
    // 例：target_path matches ("~/.ssh/**", "~/.aws/**")
    const match = expr.match(/^(\w+)\s+(\w+)\s*\((.+)\)$/s);
    if (match) {
      const fieldName = match[1];
      const funcName = match[2];
      const argsStr = match[3];
      const args = this.parseArgs(argsStr);
      const fieldValue = this.resolveField(fieldName, context);
      return this.callFunction(funcName, fieldValue, args, context);
    }

    // 格式 2：field_name function_name identifier (no parens)
    // 例：target_url not_in trusted_domains_list
    const match2 = expr.match(/^(\w+)\s+(\w+)\s+(\S+)$/);
    if (match2) {
      const fieldName = match2[1];
      const funcName = match2[2];
      const arg = match2[3].replace(/^["']|["']$/g, '');
      const fieldValue = this.resolveField(fieldName, context);
      return this.callFunction(funcName, fieldValue, [arg], context);
    }

    // 回退到简单模式（数字比较等）
    return this.evaluateSimpleExpr(expr, context);
  }

  /**
   * 调用匹配函数
   */
  private callFunction(
    funcName: string,
    fieldValue: string | string[] | null,
    args: string[],
    context: MatchContext
  ): boolean {
    switch (funcName.toLowerCase()) {
      case 'matches':
        return this.funcMatches(fieldValue, args);
      case 'contains':
        return this.funcContains(fieldValue, args);
      case 'equals':
        return this.funcEquals(fieldValue, args);
      case 'not_in':
        return this.funcNotIn(fieldValue, args, context);
      case 'in_list':
      case 'in':
        return this.funcInList(fieldValue, args);
      case 'regex_match':
        return this.funcRegexMatch(fieldValue, args);
      case 'superset_of':
        return this.funcSupersetOf(fieldValue, args, context);
      default:
        console.warn(`[ExpressionEvaluator] Unknown function: ${funcName}`);
        return false;
    }
  }

  /**
   * Glob 通配符匹配
   * 例：target_path matches ("~/.ssh/**", "~/.aws/**")
   */
  private funcMatches(value: string | string[] | null, patterns: string[]): boolean {
    if (!value) return false;
    const values = Array.isArray(value) ? value : [value];

    for (const val of values) {
      for (const pattern of patterns) {
        if (this.globMatch(val, pattern)) {
          return true;
        }
      }
    }
    return false;
  }

  /**
   * 包含检查
   * 例：command contains ("base64", "curl")
   */
  private funcContains(value: string | string[] | null, keywords: string[]): boolean {
    if (!value) return false;
    const searchIn = Array.isArray(value) ? value.join(' ') : value;

    for (const keyword of keywords) {
      if (searchIn.includes(keyword)) {
        return true;
      }
    }
    return false;
  }

  /**
   * 等值检查
   */
  private funcEquals(value: string | string[] | null, expected: string[]): boolean {
    if (!value) return false;
    return expected.some(e => value === e);
  }

  /**
   * 不在列表中
   * 例：target_url not_in trusted_domains_list
   */
  private funcNotIn(value: string | string[] | null, listRefs: string[], context: MatchContext): boolean {
    if (!value) return true; // 值为空，算不在列表中
    const values = Array.isArray(value) ? value : [value];

    // 解析列表引用
    const list = this.resolveListRef(listRefs, context);

    // 如果列表为空（引用未配置），无法判断，默认视为"在列表中"（安全放行）
    if (list.length === 0) return false;

    for (const val of values) {
      if (list.some(item => val.includes(item) || val === item)) {
        return false; // 找到匹配，则在列表中
      }
    }
    return true; // 都不匹配，确实不在列表中
  }

  /**
   * 属于列表
   */
  private funcInList(value: string | string[] | null, listValues: string[]): boolean {
    if (!value) return false;
    return listValues.some(lv => value.includes(lv) || value === lv);
  }

  /**
   * 正则匹配
   */
  private funcRegexMatch(value: string | string[] | null, patterns: string[]): boolean {
    if (!value) return false;
    const values = Array.isArray(value) ? value : [value];
    for (const v of values) {
      for (const pattern of patterns) {
        try {
          const regex = new RegExp(pattern, 'i');
          if (regex.test(v)) return true;
        } catch {
          // 无效正则，跳过
        }
      }
    }
    return false;
  }

  /**
   * 超集检查
   * 例：subagent_permissions superset_of parent_agent_permissions
   */
  private funcSupersetOf(value: string | string[] | null, refs: string[], context: MatchContext): boolean {
    if (!value) return false;
    const setA = new Set(Array.isArray(value) ? value : [value]);

    const setB = this.resolveListRef(refs, context);
    const setBSet = new Set(setB);

    // setA 是 setB 的超集 = setA 包含 setB 的所有元素
    for (const elem of setBSet) {
      if (!setA.has(elem)) return false;
    }
    return true;
  }

  /**
   * 解析参数列表
   * 支持："string", identifier, 123
   */
  private parseArgs(argsStr: string): string[] {
    const args: string[] = [];
    let current = '';
    let inQuote = false;
    let quoteChar = '';

    for (let i = 0; i < argsStr.length; i++) {
      const ch = argsStr[i];

      if (!inQuote && (ch === '"' || ch === "'")) {
        inQuote = true;
        quoteChar = ch;
        continue;
      }

      if (inQuote && ch === quoteChar) {
        inQuote = false;
        quoteChar = '';
        continue;
      }

      if (!inQuote && ch === ',') {
        args.push(current.trim());
        current = '';
        continue;
      }

      current += ch;
    }

    if (current.trim()) {
      args.push(current.trim());
    }

    return args;
  }

  /**
   * 解析字段引用
   * 例：target_path → context.target_path
   *     request_body  → context.request_body
   */
  private resolveField(fieldName: string, context: MatchContext): string | string[] | null {
    // 如果字段名是字符串字面量（被引号包围），直接返回
    if ((fieldName.startsWith('"') && fieldName.endsWith('"')) ||
        (fieldName.startsWith("'") && fieldName.endsWith("'"))) {
      return fieldName.slice(1, -1);
    }

    // 如果是数字，直接返回
    if (/^\d+$/.test(fieldName)) return fieldName;

    // 否则，从上下文提取
    const map: Record<string, keyof MatchContext> = {
      'target_path': 'target_path',
      'command_args': 'command_args',
      'command': 'command',
      'request_body': 'request_body',
      'request_body_size': 'request_body_size',
      'target_url': 'target_url',
      'target_remote': 'target_remote',
      'staged_files': 'staged_files',
      'user_original_intent': 'user_original_intent',
      'user_mentioned_repos': 'user_mentioned_repos',
      'subagent_context': 'subagent_context',
      'subagent_permissions': 'subagent_permissions',
      'parent_agent_permissions': 'parent_agent_permissions',
      'concurrent_subagent_count': 'concurrent_subagent_count',
      'subagent_task': 'subagent_task',
      'parent_agent_task': 'parent_agent_task',
      'message_content': 'message_content',
      'session_sensitive_data': 'session_sensitive_data',
      'read_file_content': 'read_file_content',
      'local_secrets': 'local_secrets',
      'internal_ip_addresses': 'internal_ip_addresses',
      'localhost_resources': 'localhost_resources',
      'user_intent_scope': 'user_intent_scope',
      'api_keys': 'api_keys',
      'credentials': 'credentials',
      'secrets': 'credentials',
      'tokens': 'tokens',
      'passwords': 'passwords',
    };

    const key = map[fieldName];
    if (key) {
      const val = context[key] as unknown;
      if (val === undefined || val === null) return null;
      if (Array.isArray(val)) return val.map(String);
      if (typeof val === 'number') return String(val);
      if (typeof val === 'string') return val;
      return String(val);
    }

    // 未映射的字段，回退到原始名称
    return fieldName;
  }

  /**
   * 解析列表引用
   * trusted_domains_list → this.trustedDomains
   */
  private resolveListRef(refs: string[], context: MatchContext): string[] {
    const result: string[] = [];

    for (const ref of refs) {
      switch (ref) {
        case 'trusted_domains_list':
          result.push(...this.trustedDomains);
          break;
        case 'session_sensitive_data':
          result.push(...(context.session_sensitive_data ?? []));
          break;
        case 'read_file_content':
          if (context.read_file_content) result.push(context.read_file_content);
          break;
        case 'local_secrets':
          result.push(...(context.local_secrets ?? []));
          break;
        case 'internal_ip_addresses':
          result.push(...(context.internal_ip_addresses ?? []));
          break;
        case 'localhost_resources':
          result.push(...(context.localhost_resources ?? []));
          break;
        case 'user_intent_scope':
          result.push(...(context.user_intent_scope ?? []));
          break;
        case 'user_mentioned_repos':
          result.push(...(context.user_mentioned_repos ?? []));
          break;
        case 'parent_agent_permissions':
          result.push(...(context.parent_agent_permissions ?? []));
          break;
        case 'api_keys':
          result.push(...(context.api_keys ?? []));
          break;
        case 'credentials':
        case 'secrets':
          result.push(...(context.credentials ?? []));
          break;
        default:
          // 可能是字面值
          result.push(ref.replace(/^["']|["']$/g, ''));
      }
    }

    return result;
  }

  /**
   * Glob 通配符匹配
   */
  private globMatch(str: string, pattern: string): boolean {
    const homeDir = os.homedir();
    // 展开 ~ 并归一化路径分隔符为 /
    const normalizedStr = str.replace(/^~/, homeDir).replace(/\\/g, '/');

    // 将 glob 转换为正则
    const regexStr = pattern
      .replace(/^~/, homeDir)
      .replace(/\\/g, '/')
      .replace(/[.+^${}()|[\]\\]/g, '\\$&') // 转义特殊字符
      .replace(/\*\*/g, '<<<GLOBSTAR>>>')      // 保留 **
      .replace(/\*/g, '[^|\\s]*')               // * → 匹配非 | 非空格字符（含 /）
      .replace(/<<<GLOBSTAR>>>/g, '.*')         // ** → 匹配任意字符（含 |）
      .replace(/\?/g, '.');                      // ? → 任意单字符

    try {
      const regex = new RegExp(`^${regexStr}$`, 'i');
      return regex.test(normalizedStr);
    } catch {
      return normalizedStr.includes(pattern.replace(/\*\*?/g, ''));
    }
  }

  /**
   * 简单表达式求值（非函数调用）
   */
  private evaluateSimpleExpr(expr: string, context: MatchContext): boolean {
    // 处理 >, < 比较
    const gtMatch = expr.match(/^(\w+)\s*>\s*(\d+)$/);
    if (gtMatch) {
      const fieldVal = Number(this.resolveField(gtMatch[1], context)) || 0;
      return fieldVal > Number(gtMatch[2]);
    }

    const ltMatch = expr.match(/^(\w+)\s*<\s*(\d+)$/);
    if (ltMatch) {
      const fieldVal = Number(this.resolveField(ltMatch[1], context)) || 0;
      return fieldVal < Number(ltMatch[2]);
    }

    // 回退：直接字符串匹配
    return false;
  }
}
