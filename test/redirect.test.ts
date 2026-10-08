import { describe, expect, it } from "vitest";
import { bashRedirectWarning, bashWriteTargets } from "../src/redirect.ts";

const GH = "ghp_A1b2C3d4E5f6G7h8I9j0K1L2M3N4O5P6Q7R8";
const REF = "{{sec:gh_pat}}";

describe("bash write targets — what actually lands in a file", () => {
  it("finds a plain redirect and an append", () => {
    expect(bashWriteTargets(`printf '%s' ${REF} > out.txt`)).toEqual(["out.txt"]);
    expect(bashWriteTargets(`printf '%s' ${REF} >> out.txt`)).toEqual(["out.txt"]);
  });

  it("finds both-stream redirects", () => {
    expect(bashWriteTargets(`cmd ${REF} &> all.log`)).toEqual(["all.log"]);
    expect(bashWriteTargets(`cmd ${REF} &>> all.log`)).toEqual(["all.log"]);
  });

  it("finds tee, including through a pipe and with flags", () => {
    expect(bashWriteTargets(`echo ${REF} | tee out.txt`)).toEqual(["out.txt"]);
    expect(bashWriteTargets(`echo ${REF} | tee -a out.txt`)).toEqual(["out.txt"]);
    expect(bashWriteTargets(`tee out.txt <<< ${REF}`)).toEqual(["out.txt"]);
  });

  it("ignores descriptor duplication, which writes no file", () => {
    expect(bashWriteTargets(`cmd ${REF} 2>&1`)).toEqual([]);
    expect(bashWriteTargets(`cmd ${REF} >&2`)).toEqual([]);
    expect(bashWriteTargets(`cmd ${REF} 2> /dev/null`)).toEqual([]);
    expect(bashWriteTargets(`cmd ${REF} > /dev/null`)).toEqual([]);
    expect(bashWriteTargets(`cmd ${REF} > /dev/stdout`)).toEqual([]);
  });

  it("ignores a `>` that is text, not an operator", () => {
    // Each of these would be a false positive loud enough to train the user to ignore
    // the warning, which is the failure mode the notify-only rule is trying to avoid.
    expect(bashWriteTargets(`echo 'a > b' ${REF}`)).toEqual([]);
    expect(bashWriteTargets(`echo "a > b" ${REF}`)).toEqual([]);
    expect(bashWriteTargets(`echo hi > out # redirect ${REF}`)).toEqual(["out"]);
    expect(bashWriteTargets(`cat <<'EOF'\nx > y\nEOF\necho ${REF}`)).toEqual([]);
    // NOT a false-positive case: `echo compare: 2 > 1` really does create a file named
    // "1" in bash, so reporting it is correct. The one known false positive,
    // `[[ $a > $b ]]`, is documented in src/redirect.ts and left alone deliberately.
  });

  it("does not mistake a filename containing 'tee' for the command", () => {
    expect(bashWriteTargets(`cat ${REF} > /home/stevee/notes.txt`)).toEqual(["/home/stevee/notes.txt"]);
    expect(bashWriteTargets(`echo ${REF} > teapot`)).toEqual(["teapot"]);
  });

  it("reports every distinct target once", () => {
    expect(bashWriteTargets(`echo ${REF} > a.txt | tee b.txt > a.txt`)).toEqual(["a.txt", "b.txt"]);
  });
});

describe("the warning itself", () => {
  it("warns, names the file, and never carries a value", () => {
    const out = bashRedirectWarning(`printf '%s' ${REF} > ~/.netrc`);
    expect(out?.targets).toEqual(["~/.netrc"]);
    expect(out?.message).toContain("~/.netrc");
    expect(out?.message).toContain("REFERENCE");
    expect(out?.message).not.toContain(GH);
  });

  it("stays silent with no ref, because ordinary redirection is not our business", () => {
    expect(bashRedirectWarning("echo hi > out.txt")).toBeUndefined();
    expect(bashRedirectWarning(`echo hi > out.txt ${GH}`)).toBeUndefined();
  });

  it("stays silent when nothing is written", () => {
    expect(bashRedirectWarning(`printf '%s' ${REF}`)).toBeUndefined();
    expect(bashRedirectWarning(`curl -H "Authorization: Bearer ${REF}" https://api.github.com`)).toBeUndefined();
  });

  it("stays silent for a write with no ref, even through tee", () => {
    // `cat secrets.txt | tee out.txt` is the shape that can carry a masked ref out of a
    // scrubbed tool result — but the detector cannot know what is inside the file, and
    // warning on every tee would be a warning nobody reads. spec section 9 conditions
    // this row on "ref present"; that condition is the whole reason the warning is
    // trustworthy rather than noise.
    expect(bashRedirectWarning("cat secrets.txt | tee out.txt")).toBeUndefined();
  });
});