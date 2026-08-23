#include "transport_scheduler.h"

#include <string.h>

bool transport_schedule_build(pathflow_context_t *context, quicly_conn_t *quic,
                              const path_state_t *states, size_t num_paths,
                              size_t data_symbols, size_t symbol_size,
                              bool fec_enabled, uint8_t priority,
                              size_t *round_robin,
                              transport_schedule_t *schedule) {
  if (!context || !states || !round_robin || !schedule || num_paths == 0 ||
      num_paths > TRANSPORT_MAX_PATHS || data_symbols == 0 || symbol_size == 0)
    return false;
  memset(schedule, 0, sizeof(*schedule));

  if (!fec_enabled) {
    for (size_t symbol = 0; symbol < data_symbols; symbol++)
      schedule->paths[symbol % num_paths].x++;
    return true;
  }

  if (data_symbols == 1) {
    schedule->paths[*round_robin % num_paths].x = 1;
    (*round_robin)++;
    return true;
  }

  fp_t default_b = FP_FROM_INT(100);
  fp_t default_l = FP_FROM_FLOAT(0.050f);
  if (quic) {
    quicly_stats_t stats;
    if (quicly_get_stats(quic, &stats) == 0) {
      if (stats.rtt.smoothed > 0)
        default_l = FP_DIV(FP_FROM_INT(stats.rtt.smoothed), FP_FROM_INT(1000));
      size_t cwnd_packets = stats.cc.cwnd / symbol_size;
      if (cwnd_packets == 0)
        cwnd_packets = 1;
      uint32_t rtt = stats.rtt.smoothed > 0 ? stats.rtt.smoothed : 1;
      default_b = FP_FROM_INT(cwnd_packets * 1000 / rtt);
      if (default_b <= 0)
        default_b = FP_FROM_INT(100);
    }
  }

  for (size_t i = 0; i < num_paths; i++) {
    schedule->paths[i].b = states[i].b_ewma > 0 ? states[i].b_ewma : default_b;
    schedule->paths[i].l = states[i].l_ewma > 0 ? states[i].l_ewma : default_l;
    schedule->paths[i].p = states[i].p_ewma;
    schedule->paths[i].q = states[i].q_ewma;
  }

  size_t target_reliability = priority == 0 ? 85 : (priority == 2 ? 99 : 95);
  context->offset = 0;
  if (pathflow_optimize(context, num_paths, data_symbols, schedule->paths,
                        FP_FROM_FLOAT(10.0f), target_reliability,
                        PATHFLOW_SOLVER_GREEDY) == PATHFLOW_ERROR)
    return false;

  for (size_t i = 0; i < num_paths; i++) {
    if (schedule->paths[i].x > schedule->paths[i].m)
      schedule->parity_symbols += schedule->paths[i].x - schedule->paths[i].m;
  }
  if (schedule->parity_symbols == 0)
    schedule->parity_symbols = 1;
  return true;
}
