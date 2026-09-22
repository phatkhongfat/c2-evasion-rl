from stable_baselines3.common.callbacks import BaseCallback
import numpy as np

class EvasionMetricsCallback(BaseCallback):
    def __init__(self, verbose=0, log_interval=2048, max_steps=10):
        super(EvasionMetricsCallback, self).__init__(verbose)
        self.log_interval = log_interval
        self.max_steps = max_steps
        self.episode_evasion_buffer = []      # Per-episode success (binary)
        self.episode_padding_buffer = []      # Per-episode padding sum
        self.episode_jitter_buffer = []       # Per-episode jitter sum
        self.episode_lengths = []
        self.episode_rewards = []
        # Accumulators for the current episode
        self.current_episode_evasion = None
        self.current_episode_padding = 0.0
        self.current_episode_jitter = 0.0
        self.current_episode_reward = 0.0

    def _on_step(self) -> bool:
        infos = self.locals.get("infos", [])
        rewards = self.locals.get("rewards", [])
        dones = self.locals.get("dones", [])

        for i, (info, reward) in enumerate(zip(infos, rewards)):
            if "evasion_success" in info:
                # Accumulate per-step metrics
                self.current_episode_evasion = info["evasion_success"]
                self.current_episode_padding += info.get("total_padding", 0.0)
                self.current_episode_jitter += info.get("total_jitter", 0.0)
                self.current_episode_reward += reward

            # Detect episode end (terminated or truncated) via the env's done flag
            done = bool(dones[i]) if i < len(dones) else (
                info.get("evasion_success", 0) == 1
                or info.get("episode_length", 0) >= self.max_steps
            )
            if done:
                # Episode ended: append the final success flag
                if self.current_episode_evasion is not None:
                    self.episode_evasion_buffer.append(self.current_episode_evasion)
                    self.episode_padding_buffer.append(self.current_episode_padding)
                    self.episode_jitter_buffer.append(self.current_episode_jitter)
                self.episode_lengths.append(info.get("episode_length", self.max_steps))
                self.episode_rewards.append(self.current_episode_reward)
                # Reset accumulators
                self.current_episode_evasion = None
                self.current_episode_padding = 0.0
                self.current_episode_jitter = 0.0
                self.current_episode_reward = 0.0

        if self.n_calls % self.log_interval == 0 and len(self.episode_evasion_buffer) > 0:
            window = min(500, len(self.episode_evasion_buffer))
            mean_evasion = np.mean(self.episode_evasion_buffer[-window:])
            mean_padding = np.mean(self.episode_padding_buffer[-window:])
            mean_jitter = np.mean(self.episode_jitter_buffer[-window:])

            self.logger.record("eval/evasion_success_rate", mean_evasion)
            self.logger.record("eval/mean_padding_used", mean_padding)
            self.logger.record("eval/mean_jitter_used", mean_jitter)

            if len(self.episode_lengths) > 0:
                self.logger.record("eval/mean_episode_length", np.mean(self.episode_lengths[-100:]))
                self.logger.record("eval/mean_episode_reward", np.mean(self.episode_rewards[-100:]))

        return True
