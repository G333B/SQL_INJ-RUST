// @generated automatically by Diesel CLI.

diesel::table! {
    infos (user_id) {
        user_id ->  Integer,
        full_name -> Nullable<Text>,
        address -> Nullable<Text>,
        age -> Nullable<Integer>,
        country -> Nullable<Text>,
        dog_name -> Nullable<Text>,
    }
}

diesel::table! {
    statuses (id) {
        id -> Nullable<Integer>,
        user_id -> Integer,
        content -> Text,
    }
}

diesel::table! {
    users (id) {
        id -> Nullable<Integer>,
        username -> Text,
        password -> Text,
    }
}

diesel::joinable!(infos -> users (user_id));
diesel::joinable!(statuses -> users (user_id));

diesel::allow_tables_to_appear_in_same_query!(
    infos,
    statuses,
    users,
);
