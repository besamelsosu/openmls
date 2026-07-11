// #[macro_use]
// extern crate clap;
// use clap::App;

use rustyline::error::ReadlineError;
use rustyline::DefaultEditor;
use std::env;
use std::io::{stdout, Write};

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
 >>>     - create group {group name}    create a new group
 >>>     - create kp                    create a new key package
 >>>     - exit                         exit the CLI
 >>>     - group {group name}           enter group submenu for operations
 >>>     - help                         print this help message
 >>>     - info                         show current user details
 >>>     - load {client name}           load the client state as a new client
 >>>     - register {client name}       register a new client
 >>>     - reset                        reset the server
 >>>     - update                       update the client state
";

const GROUP_HELP: &str = "
 >>> Group submenu commands:
 >>>     - demote {client name}         demote a user from admin
 >>>     - exit                         leave the group submenu
 >>>     - help                         print this group help message
 >>>     - info                         show details for the current group
 >>>     - invite {client name}         invite a user to the group
 >>>     - promote {client name}        promote a user to admin
 >>>     - read                         read messages sent to the group
 >>>     - remove {client name}         remove a user from the group
 >>>     - send {message}               send a message to the group
 >>>     - update                       update the client state for the group
";

fn print_help(help_text: &str) {
    print!("{help_text}");
}

fn print_user_info(client: &Option<user::User>) {
    match client {
        Some(client) => {
            let username = client.username();
            let group_names = client.group_names();
            let group_count = group_names.len();
            let contact_names = client.contact_names();
            let contact_count = contact_names.len();
            let kp_count = client.key_packages().len();

            println!(" >>> User info:");
            println!("     Username: {username}");
            println!("     Groups: {group_count}");
            println!("     Group names: {group_names:?}");
            println!("     Known contacts: {contact_count}");
            println!("     Contact names: {contact_names:?}");
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
    let messages = client.update(group_id).unwrap();
    println!(" >>> Updated client :)");
    if !messages.is_empty() {
        println!("     New messages:");
    }
    messages.iter().for_each(|cm| {
        println!("         {0} from {1}", cm.message, cm.author);
    });
    println!();
}

fn main() {
    pretty_env_logger::init();

    let stdout = stdout();
    let mut stdout = stdout.lock();
    let mut rl = DefaultEditor::new().unwrap();
    let history_path = env::temp_dir().join("openmls").join(".openmls_history.txt");
    let _ = rl.load_history(&history_path);

    println!(" >>> Welcome to the OpenMLS CLI :)\n >>> Type help to get a list of commands");
    let mut client = None;

    loop {
        stdout.flush().unwrap();

        let op = match rl.readline(">>> ") {
            Ok(line) => {
                let line = line.trim().to_owned();

                if !line.is_empty() {
                    let _ = rl.add_history_entry(line.as_str());
                }

                line
            }

            Err(ReadlineError::Interrupted) => {
                continue;
            }

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

        // Register a client.
        // There's no persistence. So once the client app stops you have to
        // register a new client.
        if let Some(client_name) = op.strip_prefix("register ") {
            match user::User::new(client_name.to_string()) {
                Ok(mut user) => {
                    user.add_key_package();
                    user.add_key_package();
                    match user.register() {
                        Ok(()) => {
                            println!("registered new client {client_name}");
                            client = Some(user);
                        }
                        Err(e) => {
                            eprintln!("Error registering client {client_name} : {e}");
                        }
                    }
                }
                Err(e) => {
                    eprintln!("Error creating client {client_name} : {e}");
                }
            }
            continue;
        }

        if let Some(client_name) = op.strip_prefix("load ") {
            match user::User::load(client_name.to_string()) {
                Ok(user) => {
                    client = Some(user);
                    println!("recovered client {client_name}");
                }
                Err(e) => eprintln!("Error recovering client {client_name} : {e}"),
            }
            continue;
        }

        // Create a new KeyPackage.
        if op == "create kp" {
            if let Some(client) = &mut client {
                client.create_kp();
                println!(" >>> New key package created");
            } else {
                println!(" >>> No client to update :(");
            }
            continue;
        }

        // Create a new group.
        if let Some(group_name) = op.strip_prefix("create group ") {
            if let Some(client) = &mut client {
                match client.create_group(group_name.to_string()) {
                    Ok(()) => {
                        println!(" >>> Created group {group_name} :)");
                    }
                    Err(e) => {
                        println!("Error creating group {group_name} : {e}");
                    }
                }
            } else {
                println!(" >>> No client to create a group :(");
            }
            continue;
        }

        // Group operations.
        if let Some(group_name) = op.strip_prefix("group ") {
            if let Some(client) = &mut client {
                loop {
                    let op2 = match rl.readline("{group_name} >>> ") {
                        Ok(line) => {
                            let line = line.trim().to_owned();

                            if !line.is_empty() {
                                let _ = rl.add_history_entry(line.as_str());
                            }

                            line
                        }

                        Err(ReadlineError::Interrupted) => {
                            continue;
                        }

                        Err(ReadlineError::Eof) => {
                            println!(">>> Leaving group");
                            break;
                        }

                        Err(err) => {
                            eprintln!("readline error: {err}");
                            break;
                        }
                    };

                    // Send a message to the group.
                    if let Some(msg) = op2.strip_prefix("send ") {
                        match client.send_msg(msg, group_name.to_string()) {
                            Ok(()) => println!("sent message to {group_name}"),
                            Err(e) => eprintln!("Error sending group message: {e:?}"),
                        }
                        continue;
                    }

                    // Invite a client to the group.
                    if let Some(new_client) = op2.strip_prefix("invite ") {
                        match client.invite(new_client.to_string(), group_name.to_string()) {
                            Ok(()) => {
                                println!("added {new_client} to group {group_name}");
                            }
                            Err(e) => {
                                eprintln!("Error inviting user: {e}");
                            }
                        }
                        continue;
                    }

                    // Remove a client from the group.
                    if let Some(rem_client) = op2.strip_prefix("remove ") {
                        match client.remove(rem_client.to_string(), group_name.to_string()) {
                            Ok(()) => {
                                println!("Removed {rem_client} from group {group_name}");
                            }
                            Err(e) => {
                                eprintln!("Error removing user: {e}");
                            }
                        }
                        continue;
                    }

                    // Promote a client to admin.
                    if let Some(promote_client) = op2.strip_prefix("promote ") {
                        match client.promote(promote_client.to_string(), group_name.to_string()) {
                            Ok(()) => {
                                println!(
                                    "Promoted {promote_client} to admin in group {group_name}"
                                );
                            }
                            Err(e) => {
                                eprintln!("Error promoting user: {e}");
                            }
                        }
                        continue;
                    }

                    // Demote a client from admin.
                    if let Some(demote_client) = op2.strip_prefix("demote ") {
                        match client.demote(demote_client.to_string(), group_name.to_string()) {
                            Ok(()) => {
                                println!(
                                    "Demoted {demote_client} from admin in group {group_name}"
                                );
                            }
                            Err(e) => {
                                eprintln!("Error demoting user: {e}");
                            }
                        }
                        continue;
                    }

                    // Request to leave the group.
                    if op2 == "leave" {
                        match client.leave(group_name.to_string()) {
                            Ok(()) => {
                                println!("Left group {group_name}");
                            }
                            Err(e) => {
                                eprintln!("Error leaving group: {e}");
                            }
                        }
                        continue;
                    }

                    // Read messages sent to the group.
                    if op2 == "read" {
                        let messages = client.read_msgs(group_name.to_string()).unwrap();
                        if let Some(messages) = messages {
                            println!("{} has received {} messages", group_name, messages.len());
                        } else {
                            println!("{group_name} has no messages");
                        }
                        continue;
                    }

                    if op2 == "help" {
                        print_help(&GROUP_HELP);
                        continue;
                    }

                    if op2 == "info" {
                        print_group_info(client, &group_name);
                        continue;
                    }

                    // Update the client state.
                    if op2 == "update" {
                        update(client, Some(group_name.to_string()));
                        continue;
                    }

                    // Exit group.
                    if op2 == "exit" {
                        println!(" >>> Leaving group");
                        break;
                    }

                    println!(" >>> Unknown group command :(");
                }
            } else {
                println!(" >>> No client :(");
            }
            continue;
        }

        if op == "info" {
            print_user_info(&client);
            continue;
        }

        // Update the client state.
        if op == "update" {
            if let Some(client) = &mut client {
                update(client, None);
            } else {
                println!(" >>> No client to update :(");
            }
            continue;
        }

        // Reset the server and client.
        if op == "reset" {
            backend::Backend::default().reset_server();
            client = None;
            println!(" >>> Reset server :)");
            continue;
        }

        if op == "exit" {
            let _ = rl.save_history(&history_path);
            println!(" >>> Goodbye!");
            break;
        }

        // Print help
        if op == "help" {
            print_help(HELP);
            continue;
        }

        println!(" >>> unknown command :(\n >>> try help");
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
    client_1
        .create_group("MLS Discussions".to_string())
        .unwrap();

    // Client 1 adds Client 2 to the group.
    client_1
        .invite("Client2".to_string(), "MLS Discussions".to_string())
        .unwrap();

    // Client 2 retrieves messages.
    client_2.update(None).unwrap();

    // Client 2 sends a message.
    client_2
        .send_msg(MESSAGE_1, "MLS Discussions".to_string())
        .unwrap();

    // Client 1 retrieves messages.
    client_1.update(None).unwrap();

    // Check that Client 1 received the message
    assert_eq!(
        client_1.read_msgs("MLS Discussions".to_string()).unwrap(),
        Some(vec![conversation::ConversationMessage::new(
            MESSAGE_1.to_owned(),
            "Client2".to_owned(),
        )])
    );

    // Client 2 tries to add Client 3 to the group (should fail).
    assert!(client_2
        .invite("Client3".to_string(), "MLS Discussions".to_string())
        .is_err());

    // Client 1 (admin) adds Client 3 to the group (should succeed).
    client_1
        .invite("Client3".to_string(), "MLS Discussions".to_string())
        .unwrap();

    // Everyone updates.
    client_1.update(None).unwrap();
    client_2.update(None).unwrap();
    client_3.update(None).unwrap();

    // Client 1 sends a message.
    client_1
        .send_msg(MESSAGE_2, "MLS Discussions".to_string())
        .unwrap();

    // Everyone updates.
    client_1.update(None).unwrap();
    client_2.update(None).unwrap();
    client_3.update(None).unwrap();

    // Check that Client 2 and Client 3 received the message
    assert_eq!(
        client_2.read_msgs("MLS Discussions".to_string()).unwrap(),
        Some(vec![conversation::ConversationMessage::new(
            MESSAGE_2.to_owned(),
            "Client1".to_owned(),
        )])
    );
    assert_eq!(
        client_3.read_msgs("MLS Discussions".to_string()).unwrap(),
        Some(vec![conversation::ConversationMessage::new(
            MESSAGE_2.to_owned(),
            "Client1".to_owned(),
        )])
    );

    // Client 2 (non-admin) tries to promote Client 3 (should fail).
    assert!(client_2
        .promote("Client3".to_string(), "MLS Discussions".to_string())
        .is_err());

    // Client 1 (admin) promotes Client 2 (should succeed).
    client_1
        .promote("Client2".to_string(), "MLS Discussions".to_string())
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
        .invite("Client4".to_string(), "MLS Discussions".to_string())
        .unwrap();

    // Everyone updates.
    client_1.update(None).unwrap();
    client_2.update(None).unwrap();
    client_3.update(None).unwrap();
    client_4.update(None).unwrap();

    // Client 3 sends a message.
    client_3
        .send_msg(MESSAGE_3, "MLS Discussions".to_string())
        .unwrap();

    // Everyone updates.
    client_1.update(None).unwrap();
    client_2.update(None).unwrap();
    client_3.update(None).unwrap();
    client_4.update(None).unwrap();

    // Check that Client 1 and Client 2 received the message
    assert_eq!(
        client_1.read_msgs("MLS Discussions".to_string()).unwrap(),
        Some(vec![
            conversation::ConversationMessage::new(MESSAGE_1.to_owned(), "Client2".to_owned()),
            conversation::ConversationMessage::new(MESSAGE_3.to_owned(), "Client3".to_owned())
        ])
    );
    assert_eq!(
        client_2.read_msgs("MLS Discussions".to_string()).unwrap(),
        Some(vec![
            conversation::ConversationMessage::new(MESSAGE_2.to_owned(), "Client1".to_owned()),
            conversation::ConversationMessage::new(MESSAGE_3.to_owned(), "Client3".to_owned())
        ])
    );

    // 1. Client 2 (admin) tries to demote Client 1 (admin) -> Should succeed.
    client_2
        .demote("Client1".to_string(), "MLS Discussions".to_string())
        .unwrap();

    // Everyone syncs the new epoch
    client_1.update(None).unwrap();
    client_2.update(None).unwrap();
    client_3.update(None).unwrap();
    client_4.update(None).unwrap();

    // 2. Double-check that Client 1 is actually demoted:
    // Client 1 (now non-admin) tries to promote Client 3 -> Should fail.
    assert!(client_1
        .promote("Client3".to_string(), "MLS Discussions".to_string())
        .is_err());

    // 3. Check both-side admin validation:
    // Client 2 (admin) tries to demote Client 3 (already a non-admin) -> Should fail.
    assert!(client_2
        .demote("Client3".to_string(), "MLS Discussions".to_string())
        .is_err());

    // 4. Test safety guard:
    // Client 2 tries to demote themselves (Client 2 is the last remaining admin) -> Should fail.
    assert!(client_2
        .demote("Client2".to_string(), "MLS Discussions".to_string())
        .is_err());
}
