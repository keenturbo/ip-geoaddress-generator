import axios from "axios";

export interface IPResponse {
  ip: string;
  debug?: {
    headers: Record<string, string | null>;
    timestamp: string;
    runtime: string;
  };
}

class IPService {
  async fetchIP(): Promise<IPResponse> {
    try {
      console.log('开始获取 IP...');
      console.log('请求 URL: /api/ip');
      
      // 调用自己的 API 路由，使用 Cloudflare 提供的请求头获取 IP
      const response = await axios.get<IPResponse>("/api/ip", {
        timeout: 10000, // 10秒超时
      });
      
      console.log('IP 获取成功:', response.data);
      console.log('调试信息:', response.data.debug);
      
      return response.data;
    } catch (error) {
      console.error('IP 获取失败');
      
      if (axios.isAxiosError(error)) {
        console.error('Axios 错误详情:');
        console.error('- 错误消息:', error.message);
        console.error('- 响应状态:', error.response?.status);
        console.error('- 响应数据:', error.response?.data);
        console.error('- 请求配置:', error.config?.url);
        
        if (error.code === 'ECONNABORTED') {
          console.error('请求超时');
        } else if (error.code === 'ERR_NETWORK') {
          console.error('网络错误');
        }
      } else {
        console.error('未知错误:', error);
      }
      
      throw error;
    }
  }
}

export const ipService = new IPService();