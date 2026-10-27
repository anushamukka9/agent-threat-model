# Honest limitations

What this tool does not do, stated plainly so nobody finds out the
hard way.

- **Static spec analysis only.** agent-threat-model reads a spec
  you wrote. It does not run your agent, inspect your code, trace
  its calls, or watch its traffic. A control your code has but
  your spec does not mention is invisible here, and a control your
  spec claims but your code does not have will be taken at face
  value.
- **Quality is bounded by the spec.** The report can only be as
  honest and complete as the description it reads. Unknown means
  absent by design, which errs toward more findings, but a spec
  that omits a whole tool omits its threats too. Garbage in,
  garbage out, with good formatting.
- **STRIDE is a lens, not a proof.** The categories help a reader
  sort threats. Several agent threats fit more than one category,
  and the mapping chosen here is a judgment call, documented per
  rule in the catalog. A threat model with no findings is not a
  proof that an agent is safe. It is a statement that this spec
  triggers none of these 23 rules.
- **No runtime behavior.** Prompt injection is a runtime event.
  This tool flags the architecture that makes it likely and
  damaging: unguarded input, broad tools, lasting credentials. It
  cannot tell you whether your guard catches any given payload.
  That is what the companion tools and your own testing are for.
- **Severity is triage guidance.** Critical, high, medium, and low
  are the catalog author's ranking for a typical deployment. Your
  data, your users, and your blast radius may rank a medium above
  a high. Re-rank freely. The evidence strings are there so you
  can.
- **The rule catalog is finite.** Twenty-three rules cover the
  failure modes I see most in agent architectures. They do not
  cover model-specific behavior, training data problems, provider
  outages, or plain bugs. New rules land as the patterns show up
  in real systems.
- **The scorecard grades the spec, not the system.** A 100/100
  means the spec describes a well-controlled architecture. Whether
  the running system matches the spec is a question for audits,
  tests, and the companion tools, not for this report.

None of this makes the tool useless. It makes it a checklist with
teeth: twenty-three named ways agent apps get hurt, checked the
same way every time, with the evidence printed next to each
finding. Claim more than that for it and you will be disappointed
in exactly the ways listed above.
