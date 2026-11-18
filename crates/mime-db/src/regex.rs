//! Linear-time Thompson NFA ERE engine for `mime.types` `regex(off, "pat")` rules.
//!
//! Supports `^`, `$`, `.`, `[...]` / `[^...]` (with ranges and escapes),
//! `(...)` grouping, `|` alternation, `*`/`+`/`?` quantifiers, and `\` escapes.
//! Guaranteed O(|pattern| * |text|) execution — immune to catastrophic backtracking.

const MAX_STATES: usize = 2048;
const MAX_DEPTH: usize = 32;

#[derive(Debug, Clone)]
enum Inst {
    Char(char),
    Any,
    Class {
        ranges: Vec<(char, char)>,
        neg: bool,
    },
    Start,
    End,
    Jmp(usize),
    Split(usize, usize),
    Match,
}

#[derive(Debug, Clone)]
enum Ast {
    Empty,
    Char(char),
    Any,
    Class {
        ranges: Vec<(char, char)>,
        neg: bool,
    },
    Start,
    End,
    Seq(Vec<Ast>),
    Alt(Vec<Ast>),
    Star(Box<Ast>),
    Plus(Box<Ast>),
    Quest(Box<Ast>),
}

/// Match ERE `pat` against `text` (POSIX `regexec` semantics: unanchored unless
/// `^` is present). Malformed or overly complex patterns fail closed (`false`).
#[must_use]
pub(crate) fn regex_match(pat: &str, text: &str) -> bool {
    let chars: Vec<char> = pat.chars().collect();
    let mut parser = Parser {
        chars: &chars,
        pos: 0,
    };
    let Some(ast) = parser.parse_alt(0) else {
        return false;
    };
    let mut prog = Vec::new();
    // Unanchored prefix: `.*?` — `Start` (`^`) naturally restricts matching to pos 0.
    prog.push(Inst::Split(3, 1));
    prog.push(Inst::Any);
    prog.push(Inst::Jmp(0));

    if !compile(&ast, &mut prog) {
        return false;
    }
    if prog.len() >= MAX_STATES {
        return false;
    }
    prog.push(Inst::Match);
    run_nfa(&prog, text)
}

enum AtomParse {
    Node(Ast),
    Skip,
    Error,
}

struct Parser<'a> {
    chars: &'a [char],
    pos: usize,
}

impl Parser<'_> {
    fn peek(&self) -> Option<char> {
        self.chars.get(self.pos).copied()
    }

    fn next(&mut self) -> Option<char> {
        let c = self.peek()?;
        self.pos += 1;
        Some(c)
    }

    fn parse_alt(&mut self, depth: usize) -> Option<Ast> {
        if depth > MAX_DEPTH {
            return None;
        }
        let mut branches = vec![self.parse_seq(depth)?];
        while self.peek() == Some('|') {
            self.next();
            branches.push(self.parse_seq(depth)?);
        }
        Some(if branches.len() == 1 {
            branches.pop().unwrap_or(Ast::Empty)
        } else {
            Ast::Alt(branches)
        })
    }

    fn parse_seq(&mut self, depth: usize) -> Option<Ast> {
        let mut items = Vec::new();
        while let Some(c) = self.peek() {
            if (c == ')' && depth > 0) || c == '|' {
                break;
            }
            let mut atom = match self.parse_atom(depth) {
                AtomParse::Node(a) => a,
                AtomParse::Skip => continue,
                AtomParse::Error => return None,
            };
            while let Some(q) = self.peek() {
                match q {
                    '*' => {
                        self.next();
                        atom = Ast::Star(Box::new(atom));
                    }
                    '+' => {
                        self.next();
                        atom = Ast::Plus(Box::new(atom));
                    }
                    '?' => {
                        self.next();
                        atom = Ast::Quest(Box::new(atom));
                    }
                    _ => break,
                }
            }
            items.push(atom);
        }
        Some(match items.len() {
            0 => Ast::Empty,
            1 => items.pop().unwrap_or(Ast::Empty),
            _ => Ast::Seq(items),
        })
    }

    fn parse_atom(&mut self, depth: usize) -> AtomParse {
        let Some(c) = self.next() else {
            return AtomParse::Error;
        };
        match c {
            '^' => AtomParse::Node(Ast::Start),
            '$' => AtomParse::Node(Ast::End),
            '.' => AtomParse::Node(Ast::Any),
            '(' => {
                let Some(inner) = self.parse_alt(depth + 1) else {
                    return AtomParse::Error;
                };
                if self.peek() == Some(')') {
                    self.next();
                }
                AtomParse::Node(inner)
            }
            '[' => AtomParse::Node(self.parse_class()),
            '\\' => {
                let esc = self.next().map_or('\\', unescape_char);
                AtomParse::Node(Ast::Char(esc))
            }
            '*' | '+' | '?' => AtomParse::Skip,
            lit => AtomParse::Node(Ast::Char(lit)),
        }
    }

    fn parse_class(&mut self) -> Ast {
        let neg = if self.peek() == Some('^') {
            self.next();
            true
        } else {
            false
        };
        let mut ranges = Vec::new();
        let mut first = true;
        while let Some(c) = self.next() {
            if c == ']' && !first {
                break;
            }
            first = false;
            let start = if c == '\\' {
                self.next().map_or('\\', unescape_char)
            } else {
                c
            };
            if self.peek() == Some('-') && self.chars.get(self.pos + 1).is_some_and(|&n| n != ']') {
                self.next(); // consume '-'
                if let Some(raw_end) = self.next() {
                    let end = if raw_end == '\\' {
                        self.next().map_or('\\', unescape_char)
                    } else {
                        raw_end
                    };
                    if start <= end {
                        ranges.push((start, end));
                    } else {
                        ranges.push((end, start));
                    }
                    continue;
                }
            }
            ranges.push((start, start));
        }
        Ast::Class { ranges, neg }
    }
}

fn unescape_char(c: char) -> char {
    match c {
        'n' => '\n',
        'r' => '\r',
        't' => '\t',
        other => other,
    }
}

fn compile(ast: &Ast, prog: &mut Vec<Inst>) -> bool {
    if prog.len() >= MAX_STATES {
        return false;
    }
    match ast {
        Ast::Empty => true,
        Ast::Char(c) => {
            prog.push(Inst::Char(*c));
            true
        }
        Ast::Any => {
            prog.push(Inst::Any);
            true
        }
        Ast::Class { ranges, neg } => {
            prog.push(Inst::Class {
                ranges: ranges.clone(),
                neg: *neg,
            });
            true
        }
        Ast::Start => {
            prog.push(Inst::Start);
            true
        }
        Ast::End => {
            prog.push(Inst::End);
            true
        }
        Ast::Seq(items) => items.iter().all(|it| compile(it, prog)),
        Ast::Alt(branches) => {
            let mut jmp_ends = Vec::with_capacity(branches.len());
            for (i, b) in branches.iter().enumerate() {
                if i + 1 < branches.len() {
                    let split_idx = prog.len();
                    prog.push(Inst::Split(split_idx + 1, 0));
                    if !compile(b, prog) {
                        return false;
                    }
                    let jmp_idx = prog.len();
                    prog.push(Inst::Jmp(0));
                    jmp_ends.push(jmp_idx);
                    let next_branch = prog.len();
                    prog[split_idx] = Inst::Split(split_idx + 1, next_branch);
                } else if !compile(b, prog) {
                    return false;
                }
            }
            let end = prog.len();
            for j in jmp_ends {
                prog[j] = Inst::Jmp(end);
            }
            true
        }
        Ast::Star(inner) => {
            let split_idx = prog.len();
            prog.push(Inst::Split(split_idx + 1, 0));
            if !compile(inner, prog) {
                return false;
            }
            prog.push(Inst::Jmp(split_idx));
            let after = prog.len();
            prog[split_idx] = Inst::Split(split_idx + 1, after);
            true
        }
        Ast::Plus(inner) => {
            let start = prog.len();
            if !compile(inner, prog) {
                return false;
            }
            let split_idx = prog.len();
            prog.push(Inst::Split(start, split_idx + 1));
            true
        }
        Ast::Quest(inner) => {
            let split_idx = prog.len();
            prog.push(Inst::Split(split_idx + 1, 0));
            if !compile(inner, prog) {
                return false;
            }
            let after = prog.len();
            prog[split_idx] = Inst::Split(split_idx + 1, after);
            true
        }
    }
}

fn add_state(
    prog: &[Inst],
    states: &mut Vec<usize>,
    visited: &mut [u32],
    gen_id: u32,
    pc: usize,
    pos: usize,
    len: usize,
) {
    let mut stack = vec![pc];
    while let Some(cur) = stack.pop() {
        if cur >= prog.len() || visited[cur] == gen_id {
            continue;
        }
        visited[cur] = gen_id;
        match prog[cur] {
            Inst::Jmp(target) => stack.push(target),
            Inst::Split(a, b) => {
                stack.push(b);
                stack.push(a);
            }
            Inst::Start => {
                if pos == 0 {
                    stack.push(cur + 1);
                }
            }
            Inst::End => {
                if pos == len {
                    stack.push(cur + 1);
                }
            }
            _ => states.push(cur),
        }
    }
}

fn run_nfa(prog: &[Inst], text: &str) -> bool {
    let chars: Vec<char> = text.chars().collect();
    let len = chars.len();
    let mut visited = vec![0u32; prog.len()];
    let mut gen_id = 1u32;
    let mut cur = Vec::new();
    let mut next = Vec::new();

    add_state(prog, &mut cur, &mut visited, gen_id, 0, 0, len);

    for (pos, &ch) in chars.iter().enumerate() {
        if cur.iter().any(|&pc| matches!(prog[pc], Inst::Match)) {
            return true;
        }
        gen_id = gen_id.wrapping_add(1).max(1);
        next.clear();
        for &pc in &cur {
            let matched = match &prog[pc] {
                Inst::Char(c) => *c == ch,
                Inst::Any => true,
                Inst::Class { ranges, neg } => {
                    let hit = ranges.iter().any(|&(lo, hi)| ch >= lo && ch <= hi);
                    if *neg {
                        !hit
                    } else {
                        hit
                    }
                }
                _ => false,
            };
            if matched {
                add_state(prog, &mut next, &mut visited, gen_id, pc + 1, pos + 1, len);
            }
        }
        std::mem::swap(&mut cur, &mut next);
        if cur.is_empty() {
            return false;
        }
    }

    cur.iter().any(|&pc| matches!(prog[pc], Inst::Match))
}
