# ANSI Terminal Colors
COLOR_RESET = "\033[0m"
COLOR_BOLD = "\033[1m"
COLOR_CYAN = "\033[36m"

def print_observability_summary(trace_metrics: dict, use_color: bool):
    print("\n" + "=" * 65)
    title = "DAY 5: OBSERVABILITY & METRICS REPORT (OpenTelemetry convention)"
    if use_color:
        print(f"{COLOR_BOLD}{COLOR_CYAN}{title.center(65)}{COLOR_RESET}")
    else:
        print(title.center(65))
    print("=" * 65)
    
    headers = f"{'Agent / Service Name':<28} | {'Latency':<8} | {'In Tokens':<9} | {'Out Tokens':<10} | {'Cost ($)':<8}"
    print(headers)
    print("-" * 65)
    
    total_time = 0.0
    total_in = 0
    total_out = 0
    total_cost = 0.0
    
    for agent, metrics in trace_metrics.items():
        dur = metrics.get("duration", 0.0)
        in_t = metrics.get("input_tokens", 0)
        out_t = metrics.get("output_tokens", 0)
        cost = metrics.get("cost", 0.0)
        
        total_time += dur
        total_in += in_t
        total_out += out_t
        total_cost += cost
        
        agent_label = agent.replace("_agent", "").capitalize()
        cost_str = f"${cost:.5f}" if cost > 0 else "$0.00"
        
        print(f"{agent_label:<28} | {dur:>6.2f}s | {in_t:>9} | {out_t:>10} | {cost_str:<8}")
        
    print("-" * 65)
    print(f"{'TOTAL (Execution Span)':<28} | {total_time:>6.2f}s | {total_in:>9} | {total_out:>10} | ${total_cost:.5f}")
    print("=" * 65 + "\n")
