import type { IPQualityResult } from "../types/ipQuality";

// ============ 环境变量 ============
const IPQS_KEY = process.env.IPQS_KEY || "";
const ABUSEIPDB_KEY = process.env.ABUSEIPDB_KEY || "";
const IP2LOCATION_KEY = process.env.IP2LOCATION_KEY || "";
const IPDATA_KEY = process.env.IPDATA_KEY || "";
const CLOUDFLARE_API_TOKEN = process.env.CLOUDFLARE_API_TOKEN || "";
const LLM_API_KEY = process.env.LLM_API_KEY || "";
const LLM_BASE_URL = process.env.LLM_BASE_URL || "";
const LLM_MODEL = process.env.LLM_MODEL || "gpt-3.5-turbo";

// ============ 内联工具函数 ============

const cache = new Map<string, { data: IPQualityResult; expires: number }>();

function cacheGet(key: string): IPQualityResult | null {
  const entry = cache.get(key);
  if (!entry) return null;
  if (Date.now() > entry.expires) {
    cache.delete(key);
    return null;
  }
  return entry.data;
}

function cacheSet(key: string, data: IPQualityResult, ttlSeconds: number): void {
  cache.set(key, { data, expires: Date.now() + ttlSeconds * 1000 });
}

async function fetchWithTimeout(
  url: string,
  timeoutMs: number,
  options?: { headers?: Record<string, string>; params?: Record<string, string> }
): Promise<Response> {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), timeoutMs);

  let finalUrl = url;
  if (options?.params) {
    const searchParams = new URLSearchParams(options.params);
    finalUrl += (url.includes("?") ? "&" : "?") + searchParams.toString();
  }

  try {
    const response = await fetch(finalUrl, {
      signal: controller.signal,
      headers: {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        ...options?.headers,
      },
    });
    return response;
  } finally {
    clearTimeout(timeoutId);
  }
}

// ✅ 重写：使用高级 Prompt 的 LLM 分析函数
async function analyzeWithLLM(
  data: Record<string, unknown>,
  ip: string
): Promise<{ reasoning: string }> {
  if (!LLM_API_KEY || !LLM_BASE_URL) {
    console.log("[LLM] 未配置 API Key 或 Base URL");
    return { reasoning: "" };
  }

  // 1. 定义系统提示词（专家角色与评分标准）
  const systemPrompt = `
# IP Quality Analysis Expert

你是一个专业的IP质量分析专家，负责根据用户提供的IP检测数据，综合分析IP的质量情况并给出使用建议。

## 分析维度与评分标准

### 1.‌ 基础属性
- **IP类型**：ISP/Residential (最优) > Mobile (优秀) > Business (良好) > Data Center/Hosting (一般)
- **原生/广播**：Native (原生) 优于 Broadcast (广播)
- **双ISP**：一致 (非双ISP) 优于 不一致 (双ISP)

### 2.‌ 风控评估（按权重排序）

#### 高权重指标 (一票否决)
- **IP2Location Proxy**: 若为 "Yes" 或 Usage Type 为 "VPN/TOR"，直接判定为高风险。
- **IPData Threats**: 若包含 abuse/tor/proxy，判定为高风险。
- **Cloudflare Radar**: Bot Score > 50 表示所在 ASN 及其自动化，需警惕。

#### 中权重指标
- **IPQS Fraud Score**: 75+ (可疑), 85+ (风险), 90+ (高风险)。
- **AbuseIPDB Score**: >0 即有黑历史，分数越高越危险。

### 3.‌ 输出要求
请直接输出 Markdown 格式的报告，不要包含 JSON 包装。报告结构如下：

## IP质量分析报告

### 🎯 综合评分：X/100 (根据风险扣分，初始100)

### 📊 核心指标评估
| 维度 | 状态 | 详细说明 |
|------|------|----------|
| IP类型 | ✅/⚠️/❌ | [类型] ([原生/广播]) |
| 欺诈风险 | ✅/⚠️/❌ | IPQS: [分数] |
| 威胁标记 | ✅/⚠️/❌ | [VPN/Proxy/Tor状态] |
| 滥用记录 | ✅/⚠️/❌ | AbuseIPDB: [分数] |
| 邻里环境 | ✅/⚠️/❌ | ASN Bot流量: [比例]% |

### 💡 深度分析
[针对 IP 类型、原生性、ASN 风险的详细解读，100字左右]

### ✅ 适用场景建议
- **推荐**：[列出适合的场景，如流媒体、游戏、注册等]
- **慎用**：[列出不适合的场景]
`;

  // 2. 组装用户数据
  const userPrompt = `
Analyze the following IP data:
IP: ${ip}
ISP: ${data.isp || 'Unknown'}
ASN: ${data.asn || data.ASN || 'Unknown'}
IP Type: ${data.ipType || 'Unknown'}
Country: ${data.country || data.countryCode || 'Unknown'}

Risk Data:
- Fraud Score (IPQS): ${data.fraudScore ?? 'N/A'}
- Abuse Score (AbuseIPDB): ${data.abuseScore ?? 'N/A'}
- IPData Threats: ${data.isThreat ? 'Detected' : 'None'}
- VPN: ${data.isVpn ? 'Yes' : 'No'}
- Proxy: ${data.isProxy ? 'Yes' : 'No'}
- Tor: ${data.isTor ? 'Yes' : 'No'}
- Hosting: ${data.isHosting ? 'Yes' : 'No'}

Inferred Data:
- Native/Broadcast: ${data.isNative ? 'Native IP' : 'Broadcast IP'}
- Dual ISP: ${data.isDualIsp ? 'Yes' : 'No'}

Additional Data:
- Cloudflare ASN Bot Traffic: ${data.cf_asn_bot_pct ? Number(data.cf_asn_bot_pct).toFixed(1) + '%' : 'N/A'}
- ASN Bot Risk: ${data.cf_asn_likely_bot ? 'HIGH (>50% bot traffic)' : 'LOW'}

请根据 System Prompt 的标准生成中文报告。`;

  try {
    console.log(`[LLM] 调用 API: ${LLM_BASE_URL}/chat/completions, Model: ${LLM_MODEL}`);
    const response = await fetch(`${LLM_BASE_URL}/chat/completions`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json; charset=utf-8",
        "Accept": "application/json; charset=utf-8",
        Authorization: `Bearer ${LLM_API_KEY}`,
      },
      body: JSON.stringify({
        model: LLM_MODEL,
        messages: [
          { role: "system", content: systemPrompt },
          { role: "user", content: userPrompt }
        ],
        max_tokens: 2000,
        temperature: 0.3, // 降低随机性，使分析更严谨
      }),
    });

    if (!response.ok) {
      // 错误信息解码
      const arrayBuffer = await response.arrayBuffer();
      const decoder = new TextDecoder('utf-8');
      const errorText = decoder.decode(arrayBuffer);
      console.error(`[LLM] API 返回错误 ${response.status}: ${errorText}`);
      return { reasoning: "" };
    }

    // 正确解码响应
    const arrayBuffer = await response.arrayBuffer();
    const decoder = new TextDecoder('utf-8');
    const text = decoder.decode(arrayBuffer);
    const result = JSON.parse(text) as { 
      choices?: Array<{ 
        message?: { content?: string }; 
        finish_reason?: string 
      }> 
    };
    
    const reasoning = result.choices?.[0]?.message?.content || "";
    
    console.log(`[LLM] 分析完成，长度: ${reasoning.length}`);
    return { reasoning };
  } catch (error) {
    console.error(`[LLM] 调用失败:`, error);
    return { reasoning: "" };
  }
}

// ============ 类型定义 ============

type MergedResult = Record<string, unknown> & { sources: string[] };

// ============ 主服务类 ============

const API_TIMEOUT = 5000;

interface ApiConfig {
  name: string;
  url?: string;
  enabled: boolean;
  headers?: Record<string, string>;
  params?: Record<string, string>;
  requiresASN?: boolean;
  buildUrl?: (asn: string) => string;
  transform: (d: Record<string, unknown>) => Record<string, unknown>;
}

export class IPQualityService {
  async check(ip: string): Promise<IPQualityResult> {
    const cacheKey = `ip-quality:${ip}`;
    const cached = cacheGet(cacheKey);
    if (cached) {
      console.log(`[IPQuality] 使用缓存数据: ${ip}`);
      return cached;
    }

    console.log(`[IPQuality] 开始检测 IP: ${ip}`);
    
    const apis = this.buildApis(ip);
    const { regularApis, asnDependentApis } = this.partitionApis(apis);

    const phase1Results = await this.callApis(regularApis);
    const merged = this.mergeResults(phase1Results);

    const asn = (merged.asn || merged.ASN || merged.as) as string | undefined;
    console.log(`[IPQuality] 获取到 ASN: ${asn || '未获取到'}`);
    
    if (asn && asnDependentApis.length > 0) {
      const asnResults = await this.callApis(asnDependentApis, asn);
      phase1Results.push(...asnResults);
    }

    const mergedResult = this.mergeResults(phase1Results);
    const enhancedResult = await this.enhanceResult(mergedResult, ip);

    cacheSet(cacheKey, enhancedResult as IPQualityResult, 900);
    return enhancedResult as IPQualityResult;
  }

  private buildApis(ip: string): ApiConfig[] {
    return [
      {
        name: "ipqs",
        url: `https://www.ipqualityscore.com/api/json/ip/${IPQS_KEY}/${ip}`,
        enabled: Boolean(IPQS_KEY),
        transform: (d) => this.transformIPQS(d),
      },
      {
        name: "ipapi",
        url: `https://ipwho.is/${ip}`,
        enabled: true,
        transform: (d) => this.transformIPApi(d),
      },
      {
        name: "abuseipdb",
        url: "https://api.abuseipdb.com/api/v2/check",
        enabled: Boolean(ABUSEIPDB_KEY),
        headers: { Key: ABUSEIPDB_KEY, Accept: "application/json" },
        params: { ipAddress: ip, maxAgeInDays: "90" },
        transform: (d) => this.transformAbuseIPDB(d),
      },
      {
        name: "ip2location",
        url: "https://api.ip2location.io/",
        enabled: Boolean(IP2LOCATION_KEY),
        params: { key: IP2LOCATION_KEY, ip },
        transform: (d) => this.transformIP2Location(d),
      },
      {
        name: "ipdata",
        url: `https://api.ipdata.co/${ip}`,
        enabled: Boolean(IPDATA_KEY),
        params: { "api-key": IPDATA_KEY },
        transform: (d) => this.transformIPData(d),
      },
      {
        name: "cloudflare_asn",
        enabled: Boolean(CLOUDFLARE_API_TOKEN),
        requiresASN: true,
        buildUrl: (asn: string) => this.buildCloudflareURL(asn),
        headers: { Authorization: `Bearer ${CLOUDFLARE_API_TOKEN}` },
        transform: (d) => this.transformCloudflare(d),
      },
    ];
  }

  private partitionApis(apis: ApiConfig[]) {
    const regularApis = apis.filter((api) => api.enabled && !api.requiresASN);
    const asnDependentApis = apis.filter((api) => api.enabled && api.requiresASN);
    return { regularApis, asnDependentApis };
  }

  private async callApis(apis: ApiConfig[], asn?: string) {
    const results = await Promise.allSettled(
      apis.map(async (api) => {
        try {
          const url = api.requiresASN && api.buildUrl ? api.buildUrl(asn!) : api.url!;
          const response = await fetchWithTimeout(url, API_TIMEOUT, {
            headers: api.headers,
            params: api.params,
          });
          
          if (!response.ok) {
            throw new Error(`HTTP ${response.status}`);
          }
          
          const data = await response.json() as Record<string, unknown>;
          return { source: api.name, data: api.transform(data) };
        } catch (error) {
          console.error(`[IPQuality] ${api.name} 失败:`, error);
          throw error;
        }
      })
    );

    return results
      .filter((result): result is PromiseFulfilledResult<{ source: string; data: Record<string, unknown> }> =>
        result.status === "fulfilled"
      )
      .map((result) => result.value);
  }

  private mergeResults(results: Array<{ source: string; data: Record<string, unknown> }>): MergedResult {
    const sources: string[] = [];
    const merged: Record<string, unknown> = {};
    const booleanFields = ['isVpn', 'isProxy', 'isTor', 'isHosting', 'isMobile'];
    
    results.forEach(result => {
      sources.push(result.source);
      Object.entries(result.data).forEach(([key, value]) => {
        if (booleanFields.includes(key)) {
          merged[key] = merged[key] === true || value === true;
        } else {
          if (value !== null && value !== undefined) {
            merged[key] = value;
          }
        }
      });
    });
    
    return { ...merged, sources };
  }

  private async enhanceResult(data: MergedResult, ip: string) {
    const isNative = this.determineNative(data);
    const isDualIsp = this.determineDualISP(data);

    const result = {
      ip,
      ...data,
      isNative,
      isDualIsp,
      ipType: this.determineIPType(data),
      timestamp: new Date().toISOString(),
    };

    if (LLM_API_KEY && LLM_BASE_URL) {
      const aiResult = await analyzeWithLLM(result, ip);
      return { ...result, aiReasoning: aiResult.reasoning };
    }

    return result;
  }

  private determineNative(data: Record<string, unknown>) {
    const geoCountry = data.countryCode || data.country_code;
    const ip2locCountry = data.ip2location_country_code;
    return geoCountry && ip2locCountry ? geoCountry === ip2locCountry : true;
  }

  private determineDualISP(data: Record<string, unknown>) {
    return data.isp && data.org && data.isp !== data.org;
  }

  private determineIPType(data: Record<string, unknown>): string {
    if (data.usageType && typeof data.usageType === 'string' && !data.usageType.includes('Premium')) {
      return data.usageType as string;
    }
    if (data.ip2location_usage_type && typeof data.ip2location_usage_type === 'string') {
      return data.ip2location_usage_type as string;
    }
    if (data.asn_type && typeof data.asn_type === 'string') {
      const asnType = data.asn_type as string;
      const typeMap: Record<string, string> = {
        'hosting': 'Data Center/Hosting',
        'isp': 'ISP/Residential',
        'business': 'Business',
        'education': 'Education/Research',
      };
      return typeMap[asnType.toLowerCase()] || asnType;
    }
    if (data.connection_type && typeof data.connection_type === 'string' && !data.connection_type.includes('Premium')) {
      return data.connection_type as string;
    }
    if (data.isHosting === true) return "Data Center/Hosting";
    if (data.isMobile === true) return "Mobile";
    if (data.isVpn === true || data.isProxy === true) return "VPN/Proxy";
    if (data.isTor === true) return "Tor Exit Node";
    return "Residential";
  }

  private transformIPQS(d: Record<string, unknown>) {
    return {
      fraudScore: d.fraud_score,
      isVpn: d.vpn,
      isProxy: d.proxy,
      isTor: d.tor,
      isHosting: Boolean(d.host),
      isMobile: d.mobile,
      connection_type: d.connection_type,
      isp: d.ISP,
      org: d.organization,
      asn: d.ASN,
      ASN: d.ASN,
    };
  }

  private transformIPApi(d: Record<string, unknown>) {
    return {
      countryCode: d.country_code,
      country: d.country_name,
      city: d.city,
      isp: d.isp,
      org: d.organisation || d.org,
      asn: d.asn,
      ASN: d.asn,
      as: d.asn,
    };
  }

  private transformAbuseIPDB(d: Record<string, unknown>) {
    const data = (d.data || {}) as Record<string, unknown>;
    return {
      abuseScore: data.abuseConfidenceScore,
      totalReports: data.totalReports,
      isWhitelisted: data.isWhitelisted,
      usageType: data.usageType,
      isp: data.isp,
      domain: data.domain,
    };
  }

  private transformIP2Location(d: Record<string, unknown>) {
    return {
      ip2location_country_code: d.country_code,
      ip2location_usage_type: d.usage_type,
      isProxy: d.is_proxy,
    };
  }

  private transformIPData(d: Record<string, unknown>) {
    const threat = (d.threat || {}) as Record<string, unknown>;
    const asn = (d.asn || {}) as Record<string, unknown>;
    return {
      isTor: threat.is_tor,
      isProxy: threat.is_proxy,
      isAnonymous: threat.is_anonymous,
      isKnownAbuser: threat.is_known_abuser,
      isKnownAttacker: threat.is_known_attacker,
      isThreat: threat.is_threat,
      asn_type: asn.type,
    };
  }

  private transformCloudflare(d: Record<string, unknown>) {
    const result = (d.result || {}) as Record<string, unknown>;
    const summary = (result.summary_0 || result.summary || {}) as Record<string, unknown>;
    return {
      cf_asn_bot_pct: summary.bot,
      cf_asn_human_pct: summary.human,
      cf_asn_likely_bot: Number(summary.bot || 0) > 50,
    };
  }

  private buildCloudflareURL(asn: string) {
    const match = asn.toString().match(/\d+/);
    if (!match) throw new Error(`Invalid ASN format: ${asn}`);
    return `https://api.cloudflare.com/client/v4/radar/http/summary/bot_class?asn=${match[0]}&dateRange=7d&format=json`;
  }
}