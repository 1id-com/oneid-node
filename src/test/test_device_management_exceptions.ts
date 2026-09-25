/**
 * Device-management server error codes raise the same typed exceptions as the
 * Python SDK (devices._DEVICE_ERROR_CODE_TO_EXCEPTION_CLASS). Mirrors oneid-sdk
 * tests/test_device_management_exceptions_and_operator_email.py.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import {
  raise_from_server_error_response, OneIDError, DeviceManagementError, DowngradeRejectedError,
  ColocationRequiredError, ColocationBindingError, ColocationSessionExpiredError, ColocationTimingViolationError,
  DeviceAlreadyBoundError, LastDeviceBurnRejectedError, HardwareLockedError, IdentityAlreadyLockedError,
  DeclaredTierCannotBeLockedError, TooManyActiveDevicesForLockError,
} from "../exceptions.js";

const expected_classes: Array<[string, new (...args: never[]) => Error]> = [
  ["DOWNGRADE_REJECTED", DowngradeRejectedError],
  ["COLOCATION_REQUIRED", ColocationRequiredError],
  ["SESSION_EXPIRED", ColocationSessionExpiredError],
  ["TIMING_VIOLATION", ColocationTimingViolationError],
  ["TPM_RESET_DETECTED", ColocationBindingError],
  ["DEVICE_ALREADY_BOUND", DeviceAlreadyBoundError],
  ["LAST_DEVICE_BURN_REJECTED", LastDeviceBurnRejectedError],
  ["HARDWARE_LOCKED", HardwareLockedError],
  ["ALREADY_LOCKED", IdentityAlreadyLockedError],
  ["DECLARED_TIER_CANNOT_LOCK", DeclaredTierCannotBeLockedError],
  ["TOO_MANY_ACTIVE_DEVICES", TooManyActiveDevicesForLockError],
];

for (const [error_code, expected_class] of expected_classes) {
  test(`server code ${error_code} raises ${expected_class.name}`, () => {
    assert.throws(() => raise_from_server_error_response(error_code, "from server"), (error: unknown) => {
      assert.ok(error instanceof expected_class);
      assert.ok(error instanceof DeviceManagementError);
      assert.ok(error instanceof OneIDError);
      assert.equal((error as Error).message, "from server");
      return true;
    });
  });
}

test("session expiry and timing violations are co-location binding errors", () => {
  assert.ok(new ColocationSessionExpiredError() instanceof ColocationBindingError);
  const timing = new ColocationTimingViolationError("too fast", 2, "high");
  assert.ok(timing instanceof ColocationBindingError);
  assert.equal(timing.elapsed_ms, 2);
  assert.equal(timing.severity, "high");
});
