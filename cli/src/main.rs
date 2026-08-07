// #[macro_use]
// extern crate clap;
// use clap::App;

use rustyline::error::ReadlineError;
use rustyline::DefaultEditor;
use std::env;
use std::io::stdout;

mod admin_list_gce;
mod backend;
mod conversation;
mod identity;
mod networking;
mod openmls_rust_persistent_crypto;
mod serialize_any_hashmap;
mod user;

const HELP: &str = "
 >>> Available commands:
     - create group                 create and enter a new UUID-named group
     - create kp                    create a new key package
     - exit                         exit the CLI
     - group {group ID prefix}      enter group submenu for operations
     - help                         print this help message
     - info                         show current user details
     - load {client name}           load the client state as a new client
     - register {client name}       register a new client
     - reset                        reset the server
     - update                       update the client state
";

const GROUP_HELP: &str = "
 >>> Group submenu commands:
     - demote {client name}         demote a user from admin
     - exit                         leave the group submenu
     - help                         print this group help message
     - info                         show details for the current group
     - invite {client name}         invite a user to the group
     - leave                        leave the group
     - promote {client name}        promote a user to admin
     - read                         read messages sent to the group
     - remove {client name}         remove a user from the group
     - send {message}               send a message to the group
     - self-update                  propose an update of your own leaf node
     - update                       update the client state for the group
";

enum Command {
    Register(String),
    Load(String),
    CreateKp,
    CreateGroup,
    Group(String),
    Info,
    Update,
    Reset,
    Help,
    Exit,
    Unknown,
}

impl Command {
    fn parse(input: &str) -> Self {
        let input = input.trim();
        if let Some(name) = input.strip_prefix("register ") {
            Self::Register(name.trim().to_string())
        } else if let Some(name) = input.strip_prefix("load ") {
            Self::Load(name.trim().to_string())
        } else if input == "create kp" {
            Self::CreateKp
        } else if input == "create group" {
            Self::CreateGroup
        } else if let Some(group) = input.strip_prefix("group ") {
            Self::Group(group.trim().to_string())
        } else if input == "info" {
            Self::Info
        } else if input == "update" {
            Self::Update
        } else if input == "reset" {
            Self::Reset
        } else if input == "help" {
            Self::Help
        } else if input == "exit" {
            Self::Exit
        } else {
            Self::Unknown
        }
    }
}

enum GroupCommand {
    Send(String),
    Invite(String),
    Remove(String),
    Promote(String),
    Demote(String),
    Leave,
    SelfUpdate,
    Read,
    Help,
    Info,
    Update,
    Exit,
    Unknown,
}

impl GroupCommand {
    fn parse(input: &str) -> Self {
        let input = input.trim();
        if let Some(msg) = input.strip_prefix("send ") {
            Self::Send(msg.trim().to_string())
        } else if let Some(name) = input.strip_prefix("invite ") {
            Self::Invite(name.trim().to_string())
        } else if let Some(name) = input.strip_prefix("remove ") {
            Self::Remove(name.trim().to_string())
        } else if let Some(name) = input.strip_prefix("promote ") {
            Self::Promote(name.trim().to_string())
        } else if let Some(name) = input.strip_prefix("demote ") {
            Self::Demote(name.trim().to_string())
        } else if input == "leave" {
            Self::Leave
        } else if input == "self-update" {
            Self::SelfUpdate
        } else if input == "read" {
            Self::Read
        } else if input == "help" {
            Self::Help
        } else if input == "info" {
            Self::Info
        } else if input == "update" {
            Self::Update
        } else if input == "exit" {
            Self::Exit
        } else {
            Self::Unknown
        }
    }
}

fn print_help(help_text: &str) {
    print!("{help_text}");
}

fn print_user_info(client: &Option<user::User>) {
    match client {
        Some(client) => {
            let username = client.username();
            let group_names = client.group_names();
            let group_count = group_names.len();
            let kp_count = client.key_packages().len();

            println!(" >>> User info:");
            println!("     Username: {username}");
            println!("     Groups: {group_count}");
            println!("     Group names: {group_names:?}");
            println!("     Key packages: {kp_count}");
        }
        None => {
            println!(" >>> No user registered or loaded.");
        }
    }
}

fn print_group_info(client: &user::User, group_name: &str) {
    match client.group_member_names(group_name) {
        Ok(member_names) => {
            let message_count = client.group_message_count(group_name).unwrap_or(0);
            let admin_names = client.group_admin_names(group_name).unwrap_or_default();

            println!(" >>> Group info:");
            println!("     Group: {group_name}");
            println!("     Members: {}", member_names.len());
            println!("     Member names: {member_names:?}");
            println!("     Admins: {}", admin_names.len());
            println!("     Admin names: {admin_names:?}");
            println!("     Messages stored locally: {message_count}");
        }
        Err(e) => {
            eprintln!(" >>> {e}");
        }
    }
}

fn update(client: &mut user::User, group_id: Option<String>) {
    match client.update(group_id) {
        Ok(messages) => {
            println!(" >>> Updated client :)");
            if !messages.is_empty() {
                println!("     New messages:");
            }
            messages.iter().for_each(|cm| {
                println!("         {0} from {1}", cm.message, cm.author);
            });
        }
        Err(e) => eprintln!(" >>> Error updating client: {e}"),
    }
}

fn handle_group_loop(rl: &mut DefaultEditor, client: &mut user::User, group_name: &str) {
    let prompt = format!("{group_name} >>> ");
    loop {
        let line = match rl.readline(&prompt) {
            Ok(line) => {
                let line = line.trim().to_owned();
                if !line.is_empty() {
                    let _ = rl.add_history_entry(line.as_str());
                }
                line
            }
            Err(ReadlineError::Interrupted) => continue,
            Err(ReadlineError::Eof) => {
                println!(">>> Leaving group");
                break;
            }
            Err(err) => {
                eprintln!("readline error: {err}");
                break;
            }
        };

        match GroupCommand::parse(&line) {
            GroupCommand::Send(msg) => match client.send_msg(&msg, group_name.to_string()) {
                Ok(()) => println!("sent message to {group_name}"),
                Err(e) => eprintln!("Error sending group message: {e:?}"),
            },
            GroupCommand::Invite(new_client) => {
                match client.invite(new_client.clone(), group_name.to_string()) {
                    Ok(()) => println!("added {new_client} to group {group_name}"),
                    Err(e) => eprintln!("Error inviting user: {e}"),
                }
            }
            GroupCommand::Remove(rem_client) => {
                match client.remove(rem_client.clone(), group_name.to_string()) {
                    Ok(()) => println!("Removed {rem_client} from group {group_name}"),
                    Err(e) => eprintln!("Error removing user: {e}"),
                }
            }
            GroupCommand::Promote(promote_client) => {
                match client.promote(promote_client.clone(), group_name.to_string()) {
                    Ok(()) => {
                        println!("Promoted {promote_client} to admin in group {group_name}")
                    }
                    Err(e) => eprintln!("Error promoting user: {e}"),
                }
            }
            GroupCommand::Demote(demote_client) => {
                match client.demote(demote_client.clone(), group_name.to_string()) {
                    Ok(()) => {
                        println!("Demoted {demote_client} from admin in group {group_name}")
                    }
                    Err(e) => eprintln!("Error demoting user: {e}"),
                }
            }
            GroupCommand::Leave => match client.leave(group_name.to_string()) {
                Ok(()) => println!("Left group {group_name}"),
                Err(e) => eprintln!("Error leaving group: {e}"),
            },
            GroupCommand::SelfUpdate => match client.self_update(group_name.to_string()) {
                Ok(()) => println!("Proposed a self-update in group {group_name}"),
                Err(e) => eprintln!("Error proposing self-update: {e}"),
            },
            GroupCommand::Read => match client.read_msgs(group_name.to_string()) {
                Ok(Some(messages)) => {
                    println!("{group_name} has received {} messages", messages.len());
                }
                _ => println!("{group_name} has no messages"),
            },
            GroupCommand::Help => print_help(GROUP_HELP),
            GroupCommand::Info => print_group_info(client, group_name),
            GroupCommand::Update => update(client, Some(group_name.to_string())),
            GroupCommand::Exit => {
                println!(" >>> Leaving group");
                break;
            }
            GroupCommand::Unknown => println!(" >>> Unknown group command :("),
        }
    }
}

fn main() {
    pretty_env_logger::init();

    let stdout = stdout();
    let mut _stdout = stdout.lock();
    let mut rl = DefaultEditor::new().unwrap();
    let history_path = env::temp_dir().join("openmls").join(".openmls_history.txt");
    let _ = rl.load_history(&history_path);

    println!(" >>> Welcome to the OpenMLS CLI :)\n >>> Type help to get a list of commands");
    let mut client = None;

    loop {
        let line = match rl.readline(">>> ") {
            Ok(line) => {
                let line = line.trim().to_owned();
                if !line.is_empty() {
                    let _ = rl.add_history_entry(line.as_str());
                }
                line
            }
            Err(ReadlineError::Interrupted) => continue,
            Err(ReadlineError::Eof) => {
                let _ = rl.save_history(&history_path);
                println!("\n >>> Goodbye!");
                break;
            }
            Err(err) => {
                eprintln!("readline error: {err}");
                break;
            }
        };

        match Command::parse(&line) {
            Command::Register(client_name) => match user::User::new(client_name.clone()) {
                Ok(mut user) => {
                    user.add_key_package();
                    user.add_key_package();
                    match user.register() {
                        Ok(()) => {
                            println!("registered new client {client_name}");
                            client = Some(user);
                        }
                        Err(e) => eprintln!("Error registering client {client_name} : {e}"),
                    }
                }
                Err(e) => eprintln!("Error creating client {client_name} : {e}"),
            },
            Command::Load(client_name) => match user::User::load(client_name.clone()) {
                Ok(user) => {
                    client = Some(user);
                    println!("recovered client {client_name}");
                }
                Err(e) => eprintln!("Error recovering client {client_name} : {e}"),
            },
            Command::CreateKp => {
                if let Some(c) = &mut client {
                    c.create_kp();
                    println!(" >>> New key package created");
                } else {
                    println!(" >>> No client to update :(");
                }
            }
            Command::CreateGroup => {
                if let Some(c) = &mut client {
                    match c.create_group() {
                        Ok(group_name) => {
                            println!(" >>> Created group {group_name} :)");
                            handle_group_loop(&mut rl, c, &group_name);
                        }
                        Err(e) => println!("Error creating group: {e}"),
                    }
                } else {
                    println!(" >>> No client to create a group :(");
                }
            }
            Command::Group(group_prefix) => {
                if let Some(c) = &mut client {
                    match c.resolve_group_prefix(&group_prefix) {
                        Ok(group_name) => handle_group_loop(&mut rl, c, &group_name),
                        Err(e) => eprintln!(" >>> {e}"),
                    }
                } else {
                    println!(" >>> No client :(");
                }
            }
            Command::Info => print_user_info(&client),
            Command::Update => {
                if let Some(c) = &mut client {
                    update(c, None);
                } else {
                    println!(" >>> No client to update :(");
                }
            }
            Command::Reset => {
                backend::Backend::default().reset_server();
                client = None;
                println!(" >>> Reset server :)");
            }
            Command::Help => print_help(HELP),
            Command::Exit => {
                let _ = rl.save_history(&history_path);
                println!(" >>> Goodbye!");
                break;
            }
            Command::Unknown => println!(" >>> unknown command :(\n >>> try help"),
        }
    }
}

#[test]
#[ignore]
fn basic_test() {
    // Reset the server before doing anything for testing.
    backend::Backend::default().reset_server();

    const MESSAGE_1: &str = "Thanks for adding me Client1.";
    const MESSAGE_2: &str = "Welcome Client3.";
    const MESSAGE_3: &str = "Thanks so much for the warm welcome! 😊";

    // Create one client
    let mut client_1 = user::User::new("Client1".to_string()).unwrap();
    client_1.add_key_package();
    client_1.add_key_package();
    client_1.register().unwrap();

    // Create another client
    let mut client_2 = user::User::new("Client2".to_string()).unwrap();
    client_2.add_key_package();
    client_2.add_key_package();
    client_2.register().unwrap();

    // Create another client
    let mut client_3 = user::User::new("Client3".to_string()).unwrap();
    client_3.add_key_package();
    client_3.add_key_package();
    client_3.register().unwrap();

    // Update the clients to know about the other clients.
    client_1.update(None).unwrap();
    client_2.update(None).unwrap();
    client_3.update(None).unwrap();

    // Client 1 creates a group.
    let group_name = client_1.create_group().unwrap();

    // Client 1 adds Client 2 to the group.
    client_1
        .invite("Client2".to_string(), group_name.clone())
        .unwrap();

    // Client 2 retrieves messages.
    client_2.update(None).unwrap();

    // Client 2 sends a message.
    client_2
        .send_msg(MESSAGE_1, group_name.clone())
        .unwrap();

    // Client 1 retrieves messages.
    client_1.update(None).unwrap();

    // Check that Client 1 received the message
    assert_eq!(
        client_1.read_msgs(group_name.clone()).unwrap(),
        Some(vec![conversation::ConversationMessage::new(
            MESSAGE_1.to_owned(),
            "Client2".to_owned(),
        )])
    );

    // Client 2 tries to add Client 3 to the group (should fail).
    assert!(client_2
        .invite("Client3".to_string(), group_name.clone())
        .is_err());

    // Client 1 (admin) adds Client 3 to the group (should succeed).
    client_1
        .invite("Client3".to_string(), group_name.clone())
        .unwrap();

    // Everyone updates.
    client_1.update(None).unwrap();
    client_2.update(None).unwrap();
    client_3.update(None).unwrap();

    // Client 1 sends a message.
    client_1
        .send_msg(MESSAGE_2, group_name.clone())
        .unwrap();

    // Everyone updates.
    client_1.update(None).unwrap();
    client_2.update(None).unwrap();
    client_3.update(None).unwrap();

    // Check that Client 2 and Client 3 received the message
    assert_eq!(
        client_2.read_msgs(group_name.clone()).unwrap(),
        Some(vec![conversation::ConversationMessage::new(
            MESSAGE_2.to_owned(),
            "Client1".to_owned(),
        )])
    );
    assert_eq!(
        client_3.read_msgs(group_name.clone()).unwrap(),
        Some(vec![conversation::ConversationMessage::new(
            MESSAGE_2.to_owned(),
            "Client1".to_owned(),
        )])
    );

    // Client 2 (non-admin) tries to promote Client 3 (should fail).
    assert!(client_2
        .promote("Client3".to_string(), group_name.clone())
        .is_err());

    // Client 1 (admin) promotes Client 2 (should succeed).
    client_1
        .promote("Client2".to_string(), group_name.clone())
        .unwrap();

    // Everyone updates.
    client_1.update(None).unwrap();
    client_2.update(None).unwrap();
    client_3.update(None).unwrap();

    // Create client 4 to verify client 2 can now invite new members
    let mut client_4 = user::User::new("Client4".to_string()).unwrap();
    client_4.add_key_package();
    client_4.add_key_package();
    client_4.register().unwrap();

    client_2.update(None).unwrap();

    // Client 2 (now admin) adds Client 4 (should succeed).
    client_2
        .invite("Client4".to_string(), group_name.clone())
        .unwrap();

    // Everyone updates.
    client_1.update(None).unwrap();
    client_2.update(None).unwrap();
    client_3.update(None).unwrap();
    client_4.update(None).unwrap();

    // Client 3 sends a message.
    client_3
        .send_msg(MESSAGE_3, group_name.clone())
        .unwrap();

    // Everyone updates.
    client_1.update(None).unwrap();
    client_2.update(None).unwrap();
    client_3.update(None).unwrap();
    client_4.update(None).unwrap();

    // Check that Client 1 and Client 2 received the message
    assert_eq!(
        client_1.read_msgs(group_name.clone()).unwrap(),
        Some(vec![
            conversation::ConversationMessage::new(MESSAGE_1.to_owned(), "Client2".to_owned()),
            conversation::ConversationMessage::new(MESSAGE_3.to_owned(), "Client3".to_owned())
        ])
    );
    assert_eq!(
        client_2.read_msgs(group_name.clone()).unwrap(),
        Some(vec![
            conversation::ConversationMessage::new(MESSAGE_2.to_owned(), "Client1".to_owned()),
            conversation::ConversationMessage::new(MESSAGE_3.to_owned(), "Client3".to_owned())
        ])
    );

    // 1. Client 2 (admin) tries to demote Client 1 (admin) -> Should succeed.
    client_2
        .demote("Client1".to_string(), group_name.clone())
        .unwrap();

    // Everyone syncs the new epoch
    client_1.update(None).unwrap();
    client_2.update(None).unwrap();
    client_3.update(None).unwrap();
    client_4.update(None).unwrap();

    // 2. Double-check that Client 1 is actually demoted:
    // Client 1 (now non-admin) tries to promote Client 3 -> Should fail.
    assert!(client_1
        .promote("Client3".to_string(), group_name.clone())
        .is_err());

    // 3. Check both-side admin validation:
    // Client 2 (admin) tries to demote Client 3 (already a non-admin) -> Should fail.
    assert!(client_2
        .demote("Client3".to_string(), group_name.clone())
        .is_err());

    // 4. Test safety guard:
    // Client 2 tries to demote themselves (Client 2 is the last remaining admin) -> Should fail.
    assert!(client_2
        .demote("Client2".to_string(), group_name.clone())
        .is_err());
}
