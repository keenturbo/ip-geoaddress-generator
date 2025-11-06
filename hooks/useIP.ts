import { useQuery } from "@tanstack/react-query";
import { ipSignal } from "@/signals/ipSignal";
import { ipService } from "@/services/ipService";
import type { IPResponse } from "@/services/ipService";

export default function useIP() {
  const IPQuery = useQuery<IPResponse, Error>({
    queryKey: ["ip"],
    queryFn: async () => {
      console.log('=== useIP Hook 开始执行 ===');
      console.log('时间:', new Date().toISOString());
      
      try {
        const response = await ipService.fetchIP();
        console.log('useIP Hook 获取到响应:', response);
        
        ipSignal.value = response.ip;
        console.log('ipSignal 已更新为:', response.ip);
        
        return response;
      } catch (error) {
        console.error('useIP Hook 捕获错误:', error);
        throw error;
      }
    },
    refetchOnWindowFocus: false, // 在窗口重新聚焦时不要重新获取数据
    retry: 2, // 失败后重试2次
    retryDelay: 1000, // 重试延迟1秒
  });

  console.log('useIP Hook 状态:');
  console.log('- isLoading:', IPQuery.isLoading);
  console.log('- error:', IPQuery.error);
  console.log('- data:', IPQuery.data);

  return {
    isLoading: IPQuery.isLoading,
    error: IPQuery.error,
  };
}