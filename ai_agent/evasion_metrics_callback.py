from stable_baselines3.common.callbacks import BaseCallback
import numpy as np

class EvasionMetricsCallback(BaseCallback):
    def __init__(self, verbose=0):
        super(EvasionMetricsCallback, self).__init__(verbose)
        self.success_buffer = []
        self.padding_buffer = []

    def _on_step(self) -> bool:
        infos = self.locals.get("infos", [])
        for info in infos:
            # Bắt trực tiếp key evasion_success từ môi trường
            if "evasion_success" in info:
                self.success_buffer.append(info["evasion_success"])
                self.padding_buffer.append(info.get("total_padding", 0.0))
                
        if self.n_calls % 2048 == 0 and len(self.success_buffer) > 0:
            mean_success_rate = np.mean(self.success_buffer[-500:])
            mean_padding = np.mean(self.padding_buffer[-500:])
            
            self.logger.record("eval/evasion_success_rate", mean_success_rate)
            self.logger.record("eval/mean_padding_used", mean_padding)
            
        return True