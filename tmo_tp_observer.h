
#ifndef TMO_TP_OBSERVER_H
#define TMO_TP_OBSERVER_H

#include <sys/time.h>
#include <stdint.h>

typedef struct tmo_tp_observer_ {

  double interval_start;
  double interval_len;
  uint64_t bytes;

  double tp_min;
  double tp_max;

} tmo_tp_observer;

void tpob_create(tmo_tp_observer *o, int interval_len);
void tpob_update(tmo_tp_observer *o, const struct timespec *now, uint32_t bytes);

double tpob_get_min(tmo_tp_observer *o);
double tpob_get_max(tmo_tp_observer *o);


#endif /* TMO_TP_OBSERVER_H */ 
