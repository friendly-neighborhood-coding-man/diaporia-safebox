// Exact integer yoctoNEAR amounts for the V2 mock workload.
export const YOCTO_PER_NEAR = 10n ** 24n;
export const CENTI_NEAR = 10n ** 22n; // 0.01 NEAR
export const y = (centi) => (BigInt(centi) * CENTI_NEAR).toString();

// Mock payment distribution (weights in percent, integer => exact).
export const AMOUNT_DISTRIBUTION = Object.freeze([
  [y(1), 50], [y(2), 30], [y(3), 10], [y(4), 5], [y(5), 3], [y(6), 2],
]);
// Hourly attack probability (percent) and its selection weights.
export const HOURLY_ATTACK_PROBABILITY = Object.freeze([[0, 10], [10, 20], [20, 40], [30, 25], [50, 5]]);
export const MAX_PAYMENT_YOCTO = y(6);
