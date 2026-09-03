#pragma once

// Internal declarations shared by the split PowerPC structurer test files.

namespace ppc_structurer_tests {

int test_ppc_ctr_loop_keeps_predecrement();
int test_ppc_float_phi_keeps_float_type_after_integer_seed();
int test_ppc_float_compare_does_not_integer_cast();
int test_ppc_casted_call_result_initializes_phi_local();
int test_ppc_void_return_merge_becomes_entry_guard();
int test_ppc_small_incidental_return_merge_is_void();
int test_ppc_memory_base_live_in_is_pointer();
int test_ppc_replicated_store_return_is_void();
int test_ppc_small_data_bases_resolve_named_globals();
int test_ppc_struct_shape_is_shared_across_pointer_aliases();
int test_ppc_struct_member_recovers_pointer_type();
int test_ppc_struct_member_recovers_nested_object();
int test_ppc_pointer_return_type_is_shared_across_calls();
int test_ppc_mixed_call_arguments_follow_callee_layout();
int test_ppc_known_float_call_binds_f1_result();
int test_ppc_annotated_float_call_selects_f1();
int test_ppc_unknown_float_call_recovers_f1_lane();
int test_ppc_frame_layout_tracks_r1_float_slots();
int test_ppc_sdk_signature_seeds_mixed_lanes();
int test_ppc_annotated_stack_argument_at_call_site();
int test_ppc_annotated_incoming_stack_argument_name();
int test_ppc_pointer_parameters_shape_stack_locals();
int test_ppc_switch_selector_prefers_bounds_operand();
int test_ppc_typed_pointer_stride_is_scaled_once();
int test_ppc_rotate_mask_pointer_stride_is_scaled_once();
int test_ppc_field_copy_run_collapses_to_memcpy();
int test_ppc_preferred_global_alias_is_rendered();
int test_ppc_hidden_sret_shifts_declared_call_arguments();
int test_ppc_small_aggregate_consumes_multiple_gprs();
int test_wii_sdk_prototype_groups();
int test_ppc_gx_mixed_signature_layout();

}  // namespace ppc_structurer_tests
