// Code generated by "stringer -output bpf_cmd_string_generated.go -type=BpfCmd"; DO NOT EDIT.

package main

import "strconv"

func _() {
	// An "invalid array index" compiler error signifies that the constant values have changed.
	// Re-run the stringer command to generate them again.
	var x [1]struct{}
	_ = x[BPF_MAP_CREATE-0]
	_ = x[BPF_MAP_LOOKUP_ELEM-1]
	_ = x[BPF_MAP_UPDATE_ELEM-2]
	_ = x[BPF_MAP_DELETE_ELEM-3]
	_ = x[BPF_MAP_GET_NEXT_KEY-4]
	_ = x[BPF_PROG_LOAD-5]
	_ = x[BPF_OBJ_PIN-6]
	_ = x[BPF_OBJ_GET-7]
	_ = x[BPF_PROG_ATTACH-8]
	_ = x[BPF_PROG_DETACH-9]
	_ = x[BPF_PROG_TEST_RUN-10]
	_ = x[BPF_PROG_GET_NEXT_ID-11]
	_ = x[BPF_MAP_GET_NEXT_ID-12]
	_ = x[BPF_PROG_GET_FD_BY_ID-13]
	_ = x[BPF_MAP_GET_FD_BY_ID-14]
	_ = x[BPF_OBJ_GET_INFO_BY_FD-15]
	_ = x[BPF_PROG_QUERY-16]
	_ = x[BPF_RAW_TRACEPOINT_OPEN-17]
	_ = x[BPF_BTF_LOAD-18]
	_ = x[BPF_BTF_GET_FD_BY_ID-19]
	_ = x[BPF_TASK_FD_QUERY-20]
	_ = x[BPF_MAP_LOOKUP_AND_DELETE_ELEM-21]
	_ = x[BPF_MAP_FREEZE-22]
	_ = x[BPF_BTF_GET_NEXT_ID-23]
	_ = x[BPF_MAP_LOOKUP_BATCH-24]
	_ = x[BPF_MAP_LOOKUP_AND_DELETE_BATCH-25]
	_ = x[BPF_MAP_UPDATE_BATCH-26]
	_ = x[BPF_MAP_DELETE_BATCH-27]
	_ = x[BPF_LINK_CREATE-28]
	_ = x[BPF_LINK_UPDATE-29]
	_ = x[BPF_LINK_GET_FD_BY_ID-30]
	_ = x[BPF_LINK_GET_NEXT_ID-31]
	_ = x[BPF_ENABLE_STATS-32]
	_ = x[BPF_ITER_CREATE-33]
	_ = x[BPF_LINK_DETACH-34]
	_ = x[BPF_PROG_BIND_MAP-35]
	_ = x[_BPF_MAX-36]
}

const _BpfCmd_name = "BPF_MAP_CREATEBPF_MAP_LOOKUP_ELEMBPF_MAP_UPDATE_ELEMBPF_MAP_DELETE_ELEMBPF_MAP_GET_NEXT_KEYBPF_PROG_LOADBPF_OBJ_PINBPF_OBJ_GETBPF_PROG_ATTACHBPF_PROG_DETACHBPF_PROG_TEST_RUNBPF_PROG_GET_NEXT_IDBPF_MAP_GET_NEXT_IDBPF_PROG_GET_FD_BY_IDBPF_MAP_GET_FD_BY_IDBPF_OBJ_GET_INFO_BY_FDBPF_PROG_QUERYBPF_RAW_TRACEPOINT_OPENBPF_BTF_LOADBPF_BTF_GET_FD_BY_IDBPF_TASK_FD_QUERYBPF_MAP_LOOKUP_AND_DELETE_ELEMBPF_MAP_FREEZEBPF_BTF_GET_NEXT_IDBPF_MAP_LOOKUP_BATCHBPF_MAP_LOOKUP_AND_DELETE_BATCHBPF_MAP_UPDATE_BATCHBPF_MAP_DELETE_BATCHBPF_LINK_CREATEBPF_LINK_UPDATEBPF_LINK_GET_FD_BY_IDBPF_LINK_GET_NEXT_IDBPF_ENABLE_STATSBPF_ITER_CREATEBPF_LINK_DETACHBPF_PROG_BIND_MAP_BPF_MAX"

var _BpfCmd_index = [...]uint16{0, 14, 33, 52, 71, 91, 104, 115, 126, 141, 156, 173, 193, 212, 233, 253, 275, 289, 312, 324, 344, 361, 391, 405, 424, 444, 475, 495, 515, 530, 545, 566, 586, 602, 617, 632, 649, 657}

func (i BpfCmd) String() string {
	if i < 0 || i >= BpfCmd(len(_BpfCmd_index)-1) {
		return "BpfCmd(" + strconv.FormatInt(int64(i), 10) + ")"
	}
	return _BpfCmd_name[_BpfCmd_index[i]:_BpfCmd_index[i+1]]
}
