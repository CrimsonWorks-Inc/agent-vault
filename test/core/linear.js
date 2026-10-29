// How a cost grows with its input, measured so a loaded machine cannot fail it.
//
// The linearity tests used to hold one run to a wall clock (3000 ms), or one
// run of each size to a ratio. On a busy machine either one fails: a single
// run can land in a pause that has nothing to do with the code. Load only
// ever adds time, so the fastest of several runs is the closest reading of
// the work itself; alternating the two sizes puts both under the same load.
// What is left is the shape: a linear cost grows with the size ratio, a
// quadratic one with its square. Not a test file itself: the glob only picks
// up *.test.js.

/**
 * The fastest time of `run(small)` and of `run(large)` over `rounds`
 * alternating rounds, and their ratio.
 */
export function growth(run, small, large, rounds = 3) {
  const time = (input) => {
    const started = process.hrtime.bigint()
    run(input)
    return Number(process.hrtime.bigint() - started) / 1e6
  }
  let fastSmall = Infinity
  let fastLarge = Infinity
  for (let i = 0; i < rounds; i++) {
    fastSmall = Math.min(fastSmall, time(small))
    fastLarge = Math.min(fastLarge, time(large))
  }
  // A floor, so a sub-millisecond small run cannot make an ordinary large one
  // look like a blow-up.
  return { small: fastSmall, large: fastLarge, ratio: fastLarge / Math.max(fastSmall, 0.5) }
}

/**
 * The bound both linearity tests use for sizes eight times apart. Linear is
 * about 8 and quadratic about 64. 24 sat too close to 8 under a loaded suite:
 * a linear scrub once measured 26 (r6 F3). 40 keeps 24 of headroom above a
 * linear reading and is still well short of a quadratic one.
 */
export const LINEAR_BOUND = 40
