// PowerPC / Wii specific structurer and emitter regressions.

#include "structurer_fail_ppc_internal.hpp"

int run_ppc_structurer_tests() {
    using namespace ppc_structurer_tests;
    int rc = 0;
    rc |= test_ppc_ctr_loop_keeps_predecrement();
    rc |= test_ppc_float_phi_keeps_float_type_after_integer_seed();
    rc |= test_ppc_float_compare_does_not_integer_cast();
    rc |= test_ppc_casted_call_result_initializes_phi_local();
    rc |= test_ppc_void_return_merge_becomes_entry_guard();
    rc |= test_ppc_small_incidental_return_merge_is_void();
    rc |= test_ppc_memory_base_live_in_is_pointer();
    rc |= test_ppc_replicated_store_return_is_void();
    rc |= test_ppc_small_data_bases_resolve_named_globals();
    rc |= test_ppc_struct_shape_is_shared_across_pointer_aliases();
    rc |= test_ppc_struct_member_recovers_pointer_type();
    rc |= test_ppc_struct_member_recovers_nested_object();
    rc |= test_ppc_pointer_return_type_is_shared_across_calls();
    rc |= test_ppc_mixed_call_arguments_follow_callee_layout();
    rc |= test_ppc_known_float_call_binds_f1_result();
    rc |= test_ppc_annotated_float_call_selects_f1();
    rc |= test_ppc_unknown_float_call_recovers_f1_lane();
    rc |= test_ppc_frame_layout_tracks_r1_float_slots();
    rc |= test_ppc_sdk_signature_seeds_mixed_lanes();
    rc |= test_ppc_annotated_stack_argument_at_call_site();
    rc |= test_ppc_annotated_incoming_stack_argument_name();
    rc |= test_ppc_pointer_parameters_shape_stack_locals();
    rc |= test_ppc_switch_selector_prefers_bounds_operand();
    rc |= test_ppc_typed_pointer_stride_is_scaled_once();
    rc |= test_ppc_rotate_mask_pointer_stride_is_scaled_once();
    rc |= test_ppc_field_copy_run_collapses_to_memcpy();
    rc |= test_ppc_preferred_global_alias_is_rendered();
    rc |= test_ppc_hidden_sret_shifts_declared_call_arguments();
    rc |= test_ppc_small_aggregate_consumes_multiple_gprs();
    rc |= test_wii_sdk_prototype_groups();
    rc |= test_ppc_gx_mixed_signature_layout();
    return rc;
}
