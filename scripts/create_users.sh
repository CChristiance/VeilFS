
# Ensure the shared group exists
if ! getent group shared >/dev/null 2>&1; then
    echo "Creating group 'shared'..."
    if ! sudo groupadd shared; then
        echo "Failed to create group 'shared'." >&2
        exit 1
    fi
fi
if ! getent group shared >/dev/null 2>&1; then
    echo "Group 'shared' still does not exist, aborting." >&2
    exit 1
fi

# Ensure each user exists and belongs to the shared group
for user in alice bob carol; do
    if id -u "$user" >/dev/null 2>&1; then
        echo "$user exists, skipping creation."
    else
        if sudo useradd -m -s /bin/bash -G shared "$user"; then
            echo "Created $user and added to shared."
        else
            echo "Failed to create $user, aborting." >&2
            exit 1
        fi
    fi

    # Covers users that already existed but aren't in the group
    if ! id -nG "$user" | tr ' ' '\n' | grep -qx shared; then
        if ! sudo usermod -aG shared "$user"; then
            echo "Failed to add $user to shared, aborting." >&2
            exit 1
        fi
        echo "Added $user to shared."
    fi

    # Final check before moving on
    if ! id -nG "$user" | tr ' ' '\n' | grep -qx shared; then
        echo "$user is not in group 'shared', aborting." >&2
        exit 1
    fi
done
