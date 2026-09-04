#[derive(Debug, Clone, PartialEq)]
pub enum Token {
    // Directives
    At(String),          // @name, @version, @requires
    // Commands
    Think,
    Shell,
    Mcp,
    Ask,
    Set,
    If,
    OnError,
    Preview,
    Parallel,
    Notify,
    Abort,
    Checkpoint,
    // Values
    Ident(String),
    StringLit(String),
    Assign,
    Colon,
    Comma,
    LParen,
    RParen,
    // Misc
    Comment(String),
    Newline,
    Eof,
}

pub struct Lexer {
    input: Vec<char>,
    pos: usize,
}

impl Lexer {
    pub fn new(source: &str) -> Self {
        Self { input: source.chars().collect(), pos: 0 }
    }

    fn peek(&self) -> Option<char> {
        self.input.get(self.pos).copied()
    }

    fn advance(&mut self) -> Option<char> {
        let c = self.input.get(self.pos).copied();
        self.pos += 1;
        c
    }

    fn skip_whitespace_no_newline(&mut self) {
        while let Some(c) = self.peek() {
            if c == ' ' || c == '\t' || c == '\r' {
                self.advance();
            } else {
                break;
            }
        }
    }

    fn read_string(&mut self) -> String {
        // skip opening quote
        self.advance();
        let mut s = String::new();
        while let Some(c) = self.peek() {
            self.advance();
            if c == '"' { break; }
            if c == '\\' {
                if let Some(esc) = self.advance() {
                    match esc {
                        'n' => s.push('\n'),
                        't' => s.push('\t'),
                        '"' => s.push('"'),
                        '\\' => s.push('\\'),
                        o => { s.push('\\'); s.push(o); }
                    }
                }
            } else {
                s.push(c);
            }
        }
        s
    }

    /// Read a balanced `{...}` or `[...]` block verbatim (including nested
    /// braces and quoted strings) so JSON values pass through the lexer intact.
    fn read_balanced(&mut self) -> String {
        let open = self.peek().unwrap();
        let close = if open == '{' { '}' } else { ']' };
        let mut depth = 0i32;
        let mut s = String::new();
        let mut in_str = false;
        let mut escaped = false;
        while let Some(c) = self.peek() {
            self.advance();
            s.push(c);
            if in_str {
                if escaped {
                    escaped = false;
                } else if c == '\\' {
                    escaped = true;
                } else if c == '"' {
                    in_str = false;
                }
                continue;
            }
            match c {
                '"' => in_str = true,
                ch if ch == open => depth += 1,
                ch if ch == close => {
                    depth -= 1;
                    if depth == 0 {
                        break;
                    }
                }
                _ => {}
            }
        }
        s
    }

    fn read_ident_or_keyword(&mut self) -> Token {
        let mut s = String::new();
        while let Some(c) = self.peek() {
            if c.is_alphanumeric() || c == '_' || c == '-' {
                s.push(c);
                self.advance();
            } else {
                break;
            }
        }
        match s.as_str() {
            "think"      => Token::Think,
            "shell"      => Token::Shell,
            "mcp"        => Token::Mcp,
            "ask"        => Token::Ask,
            "set"        => Token::Set,
            "if"         => Token::If,
            "on_error"   => Token::OnError,
            "preview"    => Token::Preview,
            "parallel"   => Token::Parallel,
            "notify"     => Token::Notify,
            "abort"      => Token::Abort,
            "checkpoint" => Token::Checkpoint,
            _            => Token::Ident(s),
        }
    }

    pub fn tokenize(mut self) -> Vec<Token> {
        let mut tokens = vec![];

        loop {
            self.skip_whitespace_no_newline();

            match self.peek() {
                None => { tokens.push(Token::Eof); break; }
                Some('\n') => {
                    self.advance();
                    tokens.push(Token::Newline);
                }
                Some('#') => {
                    // Comment — read to end of line
                    let mut comment = String::new();
                    while let Some(c) = self.peek() {
                        if c == '\n' { break; }
                        comment.push(c);
                        self.advance();
                    }
                    tokens.push(Token::Comment(comment));
                }
                Some('@') => {
                    self.advance();
                    let mut name = String::new();
                    while let Some(c) = self.peek() {
                        if c.is_alphanumeric() || c == '_' {
                            name.push(c);
                            self.advance();
                        } else {
                            break;
                        }
                    }
                    // Read the rest of the line as the value
                    self.skip_whitespace_no_newline();
                    let mut val = String::new();
                    while let Some(c) = self.peek() {
                        if c == '\n' { break; }
                        val.push(c);
                        self.advance();
                    }
                    tokens.push(Token::At(format!("{}:{}", name, val.trim_matches('"').trim())));
                }
                Some('"') => {
                    tokens.push(Token::StringLit(self.read_string()));
                }
                Some('{') | Some('[') => {
                    // Capture a balanced JSON object/array as a single raw value
                    // so `mcp http_post body={"tag":"latest"}` survives lexing.
                    tokens.push(Token::StringLit(self.read_balanced()));
                }
                Some('=') => {
                    self.advance();
                    tokens.push(Token::Assign);
                }
                Some(':') => {
                    self.advance();
                    tokens.push(Token::Colon);
                }
                Some(',') => {
                    self.advance();
                    tokens.push(Token::Comma);
                }
                Some('(') => { self.advance(); tokens.push(Token::LParen); }
                Some(')') => { self.advance(); tokens.push(Token::RParen); }
                Some(c) if c.is_alphanumeric() || c == '_' => {
                    tokens.push(self.read_ident_or_keyword());
                }
                Some(c) => {
                    // Unknown character — skip
                    self.advance();
                    let _ = c;
                }
            }
        }

        tokens
    }
}
