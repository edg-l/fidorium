use tss_esapi::Context;
use tss_esapi::attributes::NvIndexAttributesBuilder;
use tss_esapi::constants::{CapabilityType, NvIndexType};
use tss_esapi::handles::NvIndexHandle;
use tss_esapi::handles::NvIndexTpmHandle;
use tss_esapi::handles::TpmHandle;
use tss_esapi::interface_types::algorithm::HashingAlgorithm;
use tss_esapi::interface_types::resource_handles::{NvAuth, Provision};
use tss_esapi::structures::{CapabilityData, NvPublicBuilder};
use super::TpmError;

fn nv_tpm_handle(nv_index: u32) -> Result<NvIndexTpmHandle, TpmError> {
    NvIndexTpmHandle::new(nv_index)
        .map_err(|e| TpmError::Counter(e.to_string()))
}

fn get_nv_handle(ctx: &mut Context, nv_index: u32) -> Result<NvIndexHandle, TpmError> {
    let tpm_handle = nv_tpm_handle(nv_index)?;
    let obj_handle = ctx
        .tr_from_tpm_public(TpmHandle::NvIndex(tpm_handle))
        .map_err(|e| TpmError::Counter(e.to_string()))?;
    Ok(NvIndexHandle::from(obj_handle))
}

/// Check if an NV index exists without triggering TPM error logs.
fn nv_index_exists(ctx: &mut Context, nv_index: u32) -> Result<bool, TpmError> {
    let target = TpmHandle::NvIndex(nv_tpm_handle(nv_index)?);
    let (cap_data, _) = ctx
        .get_capability(CapabilityType::Handles, nv_index, 1)
        .map_err(|e| TpmError::Counter(e.to_string()))?;
    if let CapabilityData::Handles(handles) = cap_data {
        Ok(handles.as_ref().contains(&target))
    } else {
        Ok(false)
    }
}

/// Delete NV counter if it exists. Idempotent.
pub fn delete_counter(ctx: &mut Context, nv_index: u32) -> Result<(), TpmError> {
    if !nv_index_exists(ctx, nv_index)? {
        return Ok(());
    }
    let handle = get_nv_handle(ctx, nv_index)?;
    ctx.execute_with_nullauth_session(|ctx| ctx.nv_undefine_space(Provision::Owner, handle))
        .map_err(|e: tss_esapi::Error| TpmError::Counter(e.to_string()))?;
    Ok(())
}

/// Create NV counter if it doesn't exist. Idempotent.
pub fn ensure_counter(ctx: &mut Context, nv_index: u32) -> Result<(), TpmError> {
    if nv_index_exists(ctx, nv_index)? {
        return Ok(());
    }

    let tpm_handle = nv_tpm_handle(nv_index)?;
    let attrs = NvIndexAttributesBuilder::new()
        .with_nv_index_type(NvIndexType::Counter)
        .with_owner_write(true)
        .with_owner_read(true)
        .with_no_da(true)
        .build()
        .map_err(|e| TpmError::Counter(e.to_string()))?;

    let nv_public = NvPublicBuilder::new()
        .with_nv_index(tpm_handle)
        .with_index_name_algorithm(HashingAlgorithm::Sha256)
        .with_index_attributes(attrs)
        .with_data_area_size(8)
        .build()
        .map_err(|e| TpmError::Counter(e.to_string()))?;

    ctx.execute_with_nullauth_session(|ctx| {
        ctx.nv_define_space(Provision::Owner, None, nv_public)
    })
    .map_err(|e: tss_esapi::Error| TpmError::Counter(e.to_string()))?;

    // NV counters must be incremented once to initialize before they can be read.
    let handle = get_nv_handle(ctx, nv_index)?;
    ctx.execute_with_nullauth_session(|ctx| ctx.nv_increment(NvAuth::Owner, handle))
        .map_err(|e: tss_esapi::Error| TpmError::Counter(e.to_string()))?;

    Ok(())
}

/// Increment counter and return new u64 value.
pub fn increment_and_read(ctx: &mut Context, nv_index: u32) -> Result<u64, TpmError> {
    let handle = get_nv_handle(ctx, nv_index)?;
    ctx.execute_with_nullauth_session(|ctx| ctx.nv_increment(NvAuth::Owner, handle))
        .map_err(|e: tss_esapi::Error| TpmError::Counter(e.to_string()))?;
    read_counter(ctx, nv_index)
}

/// Read counter without incrementing.
pub fn read_counter(ctx: &mut Context, nv_index: u32) -> Result<u64, TpmError> {
    let handle = get_nv_handle(ctx, nv_index)?;
    let buf = ctx
        .execute_with_nullauth_session(|ctx| ctx.nv_read(NvAuth::Owner, handle, 8, 0))
        .map_err(|e: tss_esapi::Error| TpmError::Counter(e.to_string()))?;

    let bytes: [u8; 8] = buf
        .value()
        .try_into()
        .map_err(|_| TpmError::Counter("counter read returned wrong size".into()))?;

    Ok(u64::from_be_bytes(bytes))
}
