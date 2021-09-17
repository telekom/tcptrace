#include "tmo_tp_observer.h"

static double timespec_to_double(const struct timespec *a) {
  return (double) a->tv_sec + a->tv_nsec * 0.000000001;
}


void tpob_create(tmo_tp_observer *o, int interval_len) {

  //  printf("tpob_create(%p, %d)\n", o, interval_len);
  
  o->interval_start = -1.0;
  o->interval_len = (double) interval_len;
  o->bytes = 0;
  o->tp_min = -1.0;
  o->tp_max = -1.0;
}


void tpob_update(tmo_tp_observer *o, const struct timespec *tv_now, uint32_t bytes) {

  double now = timespec_to_double(tv_now);

  // printf("tpob_update(%p, %f, %d)\n", o, now, bytes);

  if (o->interval_start < 0.0) {
    o->interval_start = timespec_to_double(tv_now);
    o->bytes = bytes;
    return;
  }

  if (now - o->interval_start < o->interval_len) {
    o->bytes += bytes;
  } else {

    while (now - o->interval_start >= o->interval_len) {

      double tmp_tp = (o->bytes << 3) / o->interval_len;

      //      printf("%f %f %f %d\n", now, o->interval_start, o->interval_len, o->bytes);

      if (o->tp_min < 0.0) {

	o->tp_min = tmp_tp;
	o->tp_max = tmp_tp;

      } else { 

	if (tmp_tp < o->tp_min)
	  o->tp_min = tmp_tp;
	
	if (tmp_tp > o->tp_max)
	  o->tp_max = tmp_tp;
      }

      // printf("    tp = %f (min %f max %f)\n", tmp_tp, o->tp_min, o->tp_max);

      o->bytes = 0;
      o->interval_start += o->interval_len;
    }

    o->bytes = bytes;
  }

}


double tpob_get_min(tmo_tp_observer *o) {
  return o->tp_min / 1000.0;
}


double tpob_get_max(tmo_tp_observer *o) {
  return o->tp_max / 1000.0;
}
