#!/usr/bin/env python3
"""
Snort validation runner: evaluate agent episodes against Snort botnet detection.

Workflow:
1. Load evaluate.py results (80 episodes)
2. For each episode, synthesize pcap from mutated flows
3. Run Snort offline analysis
4. Measure detection rate: % of flows Snort still flags as malicious
5. Compare: agent vs random vs baseline (no mutation)
"""
import json
import subprocess
import sys
from pathlib import Path
from typing import List, Dict, Tuple

# Add parent to path to import from ai_agent
sys.path.insert(0, str(Path(__file__).parent.parent))

from flow_to_pcap import synthesize_flow_pcap


class SnortValidator:
    def __init__(self, snort_conf: Path, output_dir: Path):
        self.snort_conf = snort_conf
        self.output_dir = output_dir
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Check snort availability
        result = subprocess.run(['which', 'snort'], capture_output=True)
        if result.returncode != 0:
            raise RuntimeError("snort not found in PATH")
    
    def run_snort_on_pcap(self, pcap_path: Path) -> int:
        """
        Run Snort on a pcap file, return number of alerts.
        
        Args:
            pcap_path: path to pcap file
        
        Returns:
            count of alerts triggered
        """
        log_dir = self.output_dir / "snort_logs"
        log_dir.mkdir(exist_ok=True)
        
        # Run Snort in offline mode
        cmd = [
            'snort',
            '-c', str(self.snort_conf),
            '-r', str(pcap_path),
            '-l', str(log_dir),
            '-q',  # Quiet mode
            '-A', 'fast'  # Fast alert mode
        ]
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30
            )
            
            # Parse alert count from output
            # Snort outputs "Action Stats" with alert count
            alert_count = 0
            for line in result.stdout.split('\n') + result.stderr.split('\n'):
                if 'Alerts:' in line or 'ALERTS:' in line:
                    try:
                        alert_count = int(line.split(':')[-1].strip().split()[0])
                    except (ValueError, IndexError):
                        pass
            
            # Alternatively, parse snort.log.* files
            if alert_count == 0:
                # Check for unified2 output or alert file
                alert_files = list(log_dir.glob("alert*"))
                if alert_files:
                    # Count non-empty lines in alert file
                    for alert_file in alert_files:
                        with open(alert_file, 'r', errors='ignore') as f:
                            lines = [l for l in f.readlines() if l.strip() and not l.startswith('#')]
                            alert_count += len(lines)
            
            return alert_count
        
        except subprocess.TimeoutExpired:
            print(f"WARNING: Snort timed out on {pcap_path}", file=sys.stderr)
            return 0
        except Exception as e:
            print(f"ERROR running Snort on {pcap_path}: {e}", file=sys.stderr)
            return 0
    
    def validate_episode(self, episode_record: Dict) -> Tuple[int, int]:
        """
        Validate one episode: synthesize pcap and run Snort.
        
        Args:
            episode_record: dict with 'original_features' and 'mutated_features'
        
        Returns:
            (detected: 1 if Snort alerts, 0 if not; total: always 1)
        """
        # Use mutated features (the flow after agent actions)
        features = episode_record.get('mutated_features', episode_record.get('original_features', {}))
        
        # Synthesize pcap
        pcap_path = self.output_dir / f"ep_{episode_record.get('episode_id', 0)}.pcap"
        try:
            synthesize_flow_pcap(
                features,
                src_ip='192.168.1.100',
                dst_ip='10.0.0.50',
                output_path=pcap_path
            )
            
            # Run Snort
            alert_count = self.run_snort_on_pcap(pcap_path)
            detected = 1 if alert_count > 0 else 0
            
            # Clean up pcap
            pcap_path.unlink()
            
            return detected, 1
        
        except Exception as e:
            print(f"ERROR processing episode {episode_record.get('episode_id', '?')}: {e}", file=sys.stderr)
            return 0, 1
    
    def validate_episodes(self, episodes_data: List[Dict]) -> Dict[str, float]:
        """
        Validate multiple episodes.
        
        Args:
            episodes_data: list of episode records (each is a dict with episode_id, features, etc.)
        
        Returns:
            dict with metrics: detection_rate, avg_detected_per_episode, etc.
        """
        total_detected = 0
        total_flows = 0
        episode_results = []
        
        for episode_record in episodes_data:
            detected, total = self.validate_episode(episode_record)
            total_detected += detected
            total_flows += total
            episode_results.append({
                'episode': episode_record.get('episode_id', '?'),
                'detected': detected,
                'total': total,
                'detection_rate': detected / max(total, 1)
            })
            
            ep_idx = episode_record.get('episode_id', 0)
            if (ep_idx + 1) % 10 == 0:
                print(f"Processed {ep_idx + 1} episodes...")
        
        overall_detection_rate = total_detected / max(total_flows, 1)
        
        return {
            'overall_detection_rate': overall_detection_rate,
            'total_detected': total_detected,
            'total_flows': total_flows,
            'avg_detected_per_episode': total_detected / max(len(episodes_data), 1),
            'episode_results': episode_results
        }


def load_evaluation_results(eval_output_path: Path) -> Dict:
    """Load the output from ai_agent/evaluate.py"""
    with open(eval_output_path, 'r') as f:
        return json.load(f)


def main():
    """
    Main validation workflow: validate agent, random, and baseline policies.
    
    Expects run_evaluation.py to have already generated:
    - snort_validation/reports/agent_evaluation.json
    - snort_validation/reports/random_evaluation.json
    - snort_validation/reports/baseline_evaluation.json
    """
    repo_root = Path(__file__).parent.parent
    snort_conf = repo_root / "snort_validation/rules/snort.conf"
    output_dir = repo_root / "snort_validation/pcaps"
    reports_dir = repo_root / "snort_validation/reports"
    
    # Check for evaluation files
    eval_files = {
        'agent': reports_dir / "agent_evaluation.json",
        'random': reports_dir / "random_evaluation.json",
        'baseline': reports_dir / "baseline_evaluation.json"
    }
    
    missing = [name for name, path in eval_files.items() if not path.exists()]
    if missing:
        print(f"ERROR: Missing evaluation files: {', '.join(missing)}")
        print("Run snort_validation/run_evaluation.py first.")
        sys.exit(1)
    
    validator = SnortValidator(snort_conf, output_dir)
    
    all_results = {}
    
    for policy_name, eval_path in eval_files.items():
        print(f"\n{'='*70}")
        print(f"VALIDATING {policy_name.upper()} POLICY WITH SNORT")
        print(f"{'='*70}\n")
        
        with open(eval_path, 'r') as f:
            eval_data = json.load(f)
        
        episodes = eval_data.get('episodes', [])
        
        if not episodes:
            print(f"ERROR: No episodes found in {eval_path}")
            continue
        
        print(f"Validating {len(episodes)} episodes...")
        results = validator.validate_episodes(episodes)
        
        # Add XGBoost evasion rate from evaluation
        results['xgb_evasion_rate'] = eval_data.get('xgb_evasion_rate', 0)
        results['policy'] = policy_name
        
        all_results[policy_name] = results
        
        # Save individual report
        report_path = reports_dir / f"{policy_name}_snort_validation.json"
        with open(report_path, 'w') as f:
            json.dump(results, f, indent=2)
        
        print(f"\n✓ {policy_name.capitalize()} validation complete")
        print(f"  Snort Detection Rate: {results['overall_detection_rate']:.2%}")
        print(f"  XGBoost Evasion Rate: {results['xgb_evasion_rate']:.2%}")
        print(f"  Report: {report_path}")
    
    # Summary comparison
    print("\n" + "="*70)
    print("SNORT VALIDATION SUMMARY")
    print("="*70)
    print(f"{'Policy':<15} {'XGBoost Evasion':<20} {'Snort Detection':<20} {'Snort Evasion'}")
    print("-"*70)
    
    for policy_name in ['agent', 'random', 'baseline']:
        if policy_name in all_results:
            r = all_results[policy_name]
            xgb_evasion = r['xgb_evasion_rate']
            snort_detect = r['overall_detection_rate']
            snort_evasion = 1 - snort_detect
            print(f"{policy_name.capitalize():<15} {xgb_evasion:>18.1%} {snort_detect:>20.1%} {snort_evasion:>19.1%}")
    
    print("="*70)
    
    # Save combined summary
    summary_path = reports_dir / "snort_validation_summary.json"
    with open(summary_path, 'w') as f:
        json.dump(all_results, f, indent=2)
    
    print(f"\n✓ Full summary saved to: {summary_path}")


if __name__ == "__main__":
    main()
