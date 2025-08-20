import os
import json
import pandas as pd
import argparse
from pathlib import Path
from typing import Dict, List, Tuple

# Analysis results exists in the analysis_results folder
analysis_results_folder = "projects"

def get_project_result_folders() -> List[Path]:
    """Get all project result folders from the analysis results directory."""
    projects_path = Path(analysis_results_folder)
    if not projects_path.exists():
        raise FileNotFoundError(f"Analysis results folder not found: {projects_path}")
    
    return [folder for folder in projects_path.iterdir() if folder.is_dir()]

def is_vulnerable_project(project_name: str) -> bool:
    """Determine if a project contains vulnerable flows based on folder name."""
    return project_name.endswith("_vuln")

def get_llm_results_folders(project_result_folder: Path) -> List[Path]:
    """Get all LLM results folders within a project result folder."""
    llm_results_path = project_result_folder / "llm_results"
    if not llm_results_path.exists():
        return []
    
    return [folder for folder in llm_results_path.iterdir() if folder.is_dir()]

def get_triage_results(project_result_folder: Path, llm_folder: Path) -> List[Dict]:
    """Extract triage results from a specific LLM folder."""
    triage_results_path = llm_folder / "triage_results"
    triage_flows_path = llm_folder / "triaged_flows"
    
    # Check if there's a .sarif file in triage_flows (indicating pipeline completed)
    has_sarif_file = False
    if triage_flows_path.exists():
        sarif_files = list(triage_flows_path.glob("*.sarif"))
        has_sarif_file = len(sarif_files) > 0
    
    # If there's a .sarif file but no .txt files in triage_results, it means 0 judgments on 0 dataflows
    if has_sarif_file and (not triage_results_path.exists() or not list(triage_results_path.glob("*.txt"))):
        # Return a special result indicating no flows were found
        return [{"judgement": "no_flows_found"}]
    
    # Otherwise, process the normal triage results
    if not triage_results_path.exists():
        return []
    
    results = []
    for txt_file in triage_results_path.glob("*.txt"):
        try:
            with open(txt_file, 'r', encoding='utf-8') as f:
                lines = f.readlines()
                if len(lines) >= 1:
                    # Parse the first line which contains the judgment
                    judgment_line = lines[0].strip()
                    if judgment_line:
                        judgment_data = json.loads(judgment_line)
                        results.append(judgment_data)
        except (json.JSONDecodeError, FileNotFoundError) as e:
            print(f"Error reading {txt_file}: {e}")
            continue
    
    return results

def count_vulnerability_judgments(triage_results: List[Dict]) -> Tuple[int, int]:
    """Count vulnerable and non-vulnerable judgments from triage results."""
    vulnerable_count = 0
    non_vulnerable_count = 0
    
    for result in triage_results:
        judgment = result.get('judgement', '').lower()  # Note: field name is 'judgement' not 'judgment'
        if judgment == 'yes':
            vulnerable_count += 1
        elif judgment == 'no':
            non_vulnerable_count += 1
        elif judgment == 'no_flows_found':
            # When no flows are found, it means the pipeline determined no vulnerable flows exist
            # This is equivalent to judging all flows as non-vulnerable
            non_vulnerable_count += 1
    
    return vulnerable_count, non_vulnerable_count

def calculate_metrics(actual_vulnerable: bool, judged_vulnerable: int, judged_non_vulnerable: int) -> Dict:
    """Calculate accuracy, precision, recall, F1-score, and support."""
    total_flows = judged_vulnerable + judged_non_vulnerable
    if total_flows == 0:
        return {
            'accuracy': 0.0,
            'precision': 0.0,
            'recall': 0.0,
            'f1_score': 0.0,
            'support': 0
        }
    
    # Determine ground truth
    if actual_vulnerable:
        # All flows are vulnerable
        tp = judged_vulnerable  # True Positives
        tn = 0                  # True Negatives
        fp = 0                  # False Positives
        fn = judged_non_vulnerable  # False Negatives
    else:
        # No flows are vulnerable
        tp = 0                  # True Positives
        tn = judged_non_vulnerable  # True Negatives
        fp = judged_vulnerable  # False Positives
        fn = 0                  # False Negatives
    
    # Calculate metrics
    accuracy = (tp + tn) / (tp + tn + fp + fn) if (tp + tn + fp + fn) > 0 else 0.0
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1_score = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
    support = tp + fn
    
    return {
        'accuracy': accuracy,
        'precision': precision,
        'recall': recall,
        'f1_score': f1_score,
        'support': support
    }

def extract_cwe_identifier(project_name: str) -> str:
    """Extract CWE identifier from project name (everything up to first '_')."""
    return project_name.split('_')[0]

def process_project_results(target_model: str | None = None) -> Tuple[pd.DataFrame, pd.DataFrame]:
    """Process all project results and return judgment counts and metrics tables."""
    project_folders = get_project_result_folders()
    
    judgment_data = []
    metrics_data = []
    
    for project_folder in project_folders:
        project_name = project_folder.name
        cwe_identifier = extract_cwe_identifier(project_name)
        is_vulnerable = is_vulnerable_project(project_name)
        
        llm_folders = get_llm_results_folders(project_folder)
        
        for llm_folder in llm_folders:
            llm_name = llm_folder.name
            
            # Filter by target model if specified
            if target_model and llm_name != target_model:
                continue
                
            triage_results = get_triage_results(project_folder, llm_folder)
            
            if not triage_results:
                continue
            
            vulnerable_count, non_vulnerable_count = count_vulnerability_judgments(triage_results)
            total_flows = vulnerable_count + non_vulnerable_count
            
            # Add to judgment data
            judgment_data.append({
                'Project': project_name,
                'CWE': cwe_identifier,
                'LLM': llm_name,
                'Vulnerable_Judgments': vulnerable_count,
                'Non_Vulnerable_Judgments': non_vulnerable_count,
                'Total_Flows': total_flows,
                'Actual_Vulnerable': is_vulnerable
            })
            
            # Calculate and add metrics
            metrics = calculate_metrics(is_vulnerable, vulnerable_count, non_vulnerable_count)
            metrics_data.append({
                'Project': project_name,
                'CWE': cwe_identifier,
                'LLM': llm_name,
                'Accuracy': metrics['accuracy'],
                'Precision': metrics['precision'],
                'Recall': metrics['recall'],
                'F1_Score': metrics['f1_score'],
                'Support': metrics['support']
            })
    
    judgment_df = pd.DataFrame(judgment_data)
    metrics_df = pd.DataFrame(metrics_data)
    
    return judgment_df, metrics_df

def calculate_average_metrics(metrics_df: pd.DataFrame) -> pd.DataFrame:
    """Calculate average metrics across all projects for each model."""
    if metrics_df.empty:
        return pd.DataFrame()
    
    # Group by LLM and calculate averages
    avg_metrics = metrics_df.groupby('LLM').agg({
        'Accuracy': 'mean',
        'Precision': 'mean',
        'Recall': 'mean',
        'F1_Score': 'mean',
        'Support': 'sum'  # Sum support across all projects
    }).reset_index()
    
    # Add count of projects for each model
    project_counts = metrics_df.groupby('LLM').size().reset_index(name='Project_Count')
    avg_metrics = avg_metrics.merge(project_counts, on='LLM')
    
    return avg_metrics

def calculate_cwe_average_metrics(metrics_df: pd.DataFrame) -> pd.DataFrame:
    """Calculate average metrics by CWE category for each model."""
    if metrics_df.empty:
        return pd.DataFrame()
    
    # Group by CWE and LLM, then calculate averages
    cwe_avg_metrics = metrics_df.groupby(['CWE', 'LLM']).agg({
        'Accuracy': 'mean',
        'Precision': 'mean',
        'Recall': 'mean',
        'F1_Score': 'mean',
        'Support': 'sum'  # Sum support across projects in the same CWE
    }).reset_index()
    
    # Add count of projects for each CWE-LLM combination
    project_counts = metrics_df.groupby(['CWE', 'LLM']).size().reset_index(name='Project_Count')
    cwe_avg_metrics = cwe_avg_metrics.merge(project_counts, on=['CWE', 'LLM'])
    
    return cwe_avg_metrics

def display_results(judgment_df: pd.DataFrame, metrics_df: pd.DataFrame):
    """Display the results in formatted tables."""
    print("=" * 80)
    print("VULNERABILITY JUDGMENT COUNTS")
    print("=" * 80)
    if not judgment_df.empty:
        print(judgment_df.to_string(index=False))
    else:
        print("No judgment data found.")
    
    print("\n" + "=" * 80)
    print("DETAILED ACCURACY METRICS (BY PROJECT)")
    print("=" * 80)
    if not metrics_df.empty:
        # Format metrics to 4 decimal places
        formatted_metrics = metrics_df.copy()
        for col in ['Accuracy', 'Precision', 'Recall', 'F1_Score']:
            formatted_metrics[col] = formatted_metrics[col].apply(lambda x: f"{x:.4f}")
        print(formatted_metrics.to_string(index=False))
    else:
        print("No metrics data found.")
    
    # Calculate and display average metrics by CWE
    cwe_avg_metrics_df = calculate_cwe_average_metrics(metrics_df)
    print("\n" + "=" * 80)
    print("AVERAGE ACCURACY METRICS (BY CWE CATEGORY)")
    print("=" * 80)
    if not cwe_avg_metrics_df.empty:
        # Format metrics to 4 decimal places
        formatted_cwe_metrics = cwe_avg_metrics_df.copy()
        for col in ['Accuracy', 'Precision', 'Recall', 'F1_Score']:
            formatted_cwe_metrics[col] = formatted_cwe_metrics[col].apply(lambda x: f"{x:.4f}")
        print(formatted_cwe_metrics.to_string(index=False))
    else:
        print("No CWE average metrics data found.")
    
    # Calculate and display overall average metrics
    avg_metrics_df = calculate_average_metrics(metrics_df)
    print("\n" + "=" * 80)
    print("OVERALL AVERAGE ACCURACY METRICS (ACROSS ALL PROJECTS)")
    print("=" * 80)
    if not avg_metrics_df.empty:
        # Format metrics to 4 decimal places
        formatted_avg_metrics = avg_metrics_df.copy()
        for col in ['Accuracy', 'Precision', 'Recall', 'F1_Score']:
            formatted_avg_metrics[col] = formatted_avg_metrics[col].apply(lambda x: f"{x:.4f}")
        print(formatted_avg_metrics.to_string(index=False))
    else:
        print("No overall average metrics data found.")

def main():
    """Main function to process and display results."""
    parser = argparse.ArgumentParser(description='Calculate vulnerability analysis results and metrics')
    parser.add_argument('--model', type=str, help='Filter results for a specific model (e.g., deepseek, deepseek-reasoner)')
    args = parser.parse_args()
    
    try:
        if args.model:
            print(f"Processing analysis results for model: {args.model}")
        else:
            print("Processing analysis results for all models...")
            
        judgment_df, metrics_df = process_project_results(args.model)
        
        if judgment_df.empty:
            print(f"No results found for model: {args.model}" if args.model else "No results found")
            return
        
        display_results(judgment_df, metrics_df)
        
        # Save results to CSV files
        model_suffix = f"_{args.model}" if args.model else ""
        judgment_df.to_csv(f'vulnerability_judgments{model_suffix}.csv', index=False)
        metrics_df.to_csv(f'accuracy_metrics{model_suffix}.csv', index=False)
        
        # Save CWE metrics to CSV
        cwe_avg_metrics_df = calculate_cwe_average_metrics(metrics_df)
        if not cwe_avg_metrics_df.empty:
            cwe_avg_metrics_df.to_csv(f'cwe_average_accuracy_metrics{model_suffix}.csv', index=False)
            print(f"\nResults saved to:")
            print(f"  - vulnerability_judgments{model_suffix}.csv")
            print(f"  - accuracy_metrics{model_suffix}.csv")
            print(f"  - cwe_average_accuracy_metrics{model_suffix}.csv")
        else:
            print(f"\nResults saved to 'vulnerability_judgments{model_suffix}.csv' and 'accuracy_metrics{model_suffix}.csv'")
        
    except Exception as e:
        print(f"Error processing results: {e}")

if __name__ == "__main__":
    main()

# Ignore everything below for now:
# Check sinks on each flow in flow prompt
# Each identified sink should be on vuln

# We should also check the sources
    # Some flows to a sink might be missed, but other flows might go to the same sinks
    # Manually check the source specification
# Do the same for sinks if the time is there