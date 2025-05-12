// @generated automatically by Diesel CLI.

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

diesel::joinable!(statuses -> users (user_id));

diesel::allow_tables_to_appear_in_same_query!(
    statuses,
    users,
);
