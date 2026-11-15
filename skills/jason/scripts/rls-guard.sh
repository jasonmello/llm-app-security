#!/usr/bin/env bash
# Heuristic RLS guard for Supabase migrations (no database needed).
# Fails when a public table's final state after all migrations (in file order)
# is "RLS off"; warns on policies using (true). Strips comments and $$ bodies,
# handles quoted identifiers, ONLY, IF [NOT] EXISTS, unlogged/temp tables.
# Ignores RLS statements inside string literals and tracks DROP TABLE.
# Limits: no rename tracking; only the public schema (add schemas exposed
# in supabase/config.toml [api] schemas). Authoritative check: the db-rules job
# in templates/pr-gates.yml (queries pg_class after `supabase db start`).
# ship-gate.cjs contains a stronger version of this check (single-pass SQL
# lexer, renames, SET SCHEMA, multi-table DROP); prefer it.
# Usage: bash rls-guard.sh [repo-root]
set -euo pipefail
cd "${1:-.}"
[ -d supabase/migrations ] || { echo "no supabase/migrations: skipped"; exit 0; }
[ -n "$(find -L supabase/migrations/ -name '*.sql' -print -quit)" ] || { echo "no .sql migrations: skipped"; exit 0; }
# Exit 1 on failure on every platform (GNU xargs turns a child's exit 1 into 123).
if find -L supabase/migrations/ -name '*.sql' -print0 | sort -z | xargs -0 -r perl -0777 -e '
  my $id = qr/(?:"(?:[^"]|"")+"|[A-Za-z_][A-Za-z0-9_\$]*)/;
  my (%rls, %src); my $fail = 0;
  sub norm { my $n = shift; $n =~ /^"/ ? substr($n,1,-1) =~ s/""/"/gr : lc $n }
  for my $f (@ARGV) {
    open my $fh, "<", $f or die "$f: $!"; local $_ = <$fh>;
    s{/\*.*?\*/}{ }gs; s{--[^\n]*}{ }g;               # strip comments
    s{\$(\w*)\$.*?\$\1\$}{ }gs; s/\s+/ /g;             # strip $$ bodies, squash whitespace
    print "::warning file=${f}::policy open to everyone: $1\n"
      while /\b(create policy .{0,200}?(?:using|with check) ?\( ?(?:true|1 ?= ?1|auth\.role\(\) ?= ?'"'"'authenticated'"'"'|auth\.uid\(\) is not null) ?\))/gi;
    s{\bE'"'"'(?:[^'"'"'\\]|\\.|'"'"''"'"')*'"'"'}{'"'"''"'"'}gi; s{'"'"'(?:[^'"'"']|'"'"''"'"')*'"'"'}{'"'"''"'"'}g;   # strip string literals
    while (/\b(?:create (temp |temporary |global temp |local temp )?(?:unlogged )?table (?:if not exists )?(?:($id)\.)?($id)|alter table (?:if exists )?(?:only )?(?:($id)\.)?($id) (enable|disable) row level security|drop table (?:if exists )?(?:($id)\.)?($id))/gi) {
      my ($tmp, $cs, $ct, $as, $at, $op, $ds, $dt) = ($1, $2, $3, $4, $5, $6, $7, $8);
      if (defined $dt) {                               # DROP TABLE
        next if defined $ds && norm($ds) ne "public";
        delete $rls{norm($dt)}; delete $src{norm($dt)}; next;
      }
      if (defined $ct) {                               # CREATE TABLE
        next if $tmp || (defined $cs && norm($cs) ne "public");
        my $t = norm($ct); $rls{$t} //= 0; $src{$t} //= $f;
      } else {                                         # ALTER TABLE ... RLS
        next if defined $as && norm($as) ne "public";
        my $t = norm($at); $rls{$t} = lc($op) eq "enable" ? 1 : 0 if exists $rls{$t};
      }
    }
  }
  for (sort keys %rls) { next if $rls{$_}; print "::error file=$src{$_}::public.$_ has no RLS after all migrations\n"; $fail = 1 }
  my $n = scalar keys %rls;
  print $n ? "OK: RLS enabled on all $n public table(s)\n" : "no public tables found in migrations\n" unless $fail;
  exit $fail;
'
then exit 0; else exit 1; fi
