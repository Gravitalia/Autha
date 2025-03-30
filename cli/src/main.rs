use clap::{command, Parser as _};
use clap_derive::{Parser, Subcommand};
use rand::{distributions::Alphanumeric, Rng};
use sqlx::PgPool;

const DEFAULT_PG_URL: &str = "postgres://postgres:postgres@localhost:5432/autha";

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[command(subcommand)]
    cmd: Commands,
}

#[derive(Debug, Clone, clap::ValueEnum)]
enum Type {
    Add,
    Remove,
}

#[derive(Subcommand, Debug, Clone)]
enum Commands {
    /// Create or remove invitation code.
    Invite {
        r#type: Type,
        /// To create an invitation with a specified code.
        #[clap(long, short)]
        code: Option<String>,
        /// If code is genereated randomly, what size should it be?
        #[clap(long, short)]
        size: Option<usize>,
    },
}

#[tokio::main]
async fn main() {
    let postgres =
        PgPool::connect(&std::env::var("POSTGRES_URL").unwrap_or_else(|_| DEFAULT_PG_URL.into()))
            .await
            .expect("Cannot connect to PostgreSQL database.");

    let args = Args::parse();
    match args.cmd {
        Commands::Invite { r#type, code, size } => match r#type {
            Type::Add => {
                let code = match code {
                    Some(code) => code,
                    None => rand::thread_rng()
                        .sample_iter(&Alphanumeric)
                        .take(size.unwrap_or(7))
                        .map(char::from)
                        .collect(),
                };

                sqlx::query!(r#"INSERT INTO "invite_codes" (code) VALUES ($1)"#, code)
                    .execute(&postgres)
                    .await
                    .expect("Are tables already created?");

                println!("Invite code {:?} has been created!", code);
            }
            Type::Remove => {
                let code = code.unwrap();
                sqlx::query!(r#"DELETE FROM "invite_codes" WHERE code = $1"#, code)
                    .execute(&postgres)
                    .await
                    .expect("Are tables already created?");

                println!("Invite code {:?} has been deleted.", code);
            }
        },
    }
}
