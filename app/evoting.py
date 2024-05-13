import streamlit as st
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import os
import random

key_file_path = "rsa_key.pem"
candidates = ["Captain America", "Iron Man", "Thor"]

st.set_page_config(
    page_title="Avengers Leader Election (Homomorphic Encryption)",
    page_icon=":shield:",
    layout="wide",
)


def load_or_generate_keys():
    if os.path.exists(key_file_path):
        with open(key_file_path, "rb") as f:
            key = RSA.import_key(f.read())
    else:
        key = RSA.generate(2048)
        with open(key_file_path, "wb") as f:
            f.write(key.export_key())
    return key


key = load_or_generate_keys()
public_key = key.publickey()
encryptor = PKCS1_OAEP.new(public_key)
decryptor = PKCS1_OAEP.new(key)

votes_dir = "votes"
os.makedirs(votes_dir, exist_ok=True)


def encrypt_vote(vote):
    encrypted_vote = encryptor.encrypt(vote.encode())
    return encrypted_vote


def decrypt_vote(encrypted_vote):
    try:
        decrypted_vote = decryptor.decrypt(encrypted_vote)
        return decrypted_vote.decode()
    except ValueError as e:
        print("Decryption failed:", e)
        return None


def cast_vote(voter_id, candidate):
    encrypted_vote = encrypt_vote(candidate)
    file_path = os.path.join(votes_dir, f"{voter_id}.txt")
    with open(file_path, "wb") as file:
        file.write(encrypted_vote)
    st.success(f"Vote cast for {candidate}")


def tally_votes(n, t, p):
    vote_counts = {}
    for filename in os.listdir(votes_dir):
        file_path = os.path.join(votes_dir, filename)
        with open(file_path, "rb") as file:
            encrypted_vote = file.read()
            candidate = decrypt_vote(encrypted_vote)
            if candidate:
                vote_counts[candidate] = vote_counts.get(candidate, 0) + 1

    if vote_counts:
        winner = max(vote_counts, key=vote_counts.get)
        max_votes = max(vote_counts.values())
        winners = [
            candidate for candidate, votes in vote_counts.items() if votes == max_votes
        ]
        if len(winners) == 1:
            winner = winners[0]

            with open("winner.txt", "w") as f:
                party_ids = random.sample(range(1, p + 1), n)
                f.write(f"{t} {p} {' '.join(map(str, party_ids))}\n")
                winner_index = candidates.index(winner)
                f.write(f"{winner_index}")

            if n >= t:
                os.system("cd ..; make bin/tlwetn && ./bin/tlwetn > ./app/results.txt")
                while not os.path.exists("results.txt"):
                    pass

                with open("results.txt", "r") as f:
                    result = f.read()

                st.sidebar.code(f"### Results\n{result}", language="markdown")

                st.success(f"Winner: {winner} with {vote_counts[winner]} votes")
            else:
                st.error(
                    f"Insufficient election officials present. Need at least {t} officials to be able to decrypt the winner and validate the election."
                )
        else:
            st.error(
                f"Tiebreaker: Multiple candidates ({', '.join(winners)}) have the same number of votes ({max_votes})."
            )
    else:
        st.error("No votes cast yet.")


def main():
    st.sidebar.title("Voter Panel")
    st.sidebar.info("Enter your voter ID to cast your vote.")
    voter_id = st.sidebar.text_input("Enter your voter ID:")

    st.sidebar.title("Admin Panel")
    st.sidebar.info("Use the admin panel to tally the votes and declare the winner.")

    n = st.sidebar.number_input(
        "Election Officials Present:", min_value=1, value=2, step=1
    )
    t = st.sidebar.number_input(
        "Required Election Officials (`t`):", min_value=1, value=6, step=1
    )
    p = st.sidebar.number_input(
        "Total Election Officials (`p`):", min_value=1, value=10, step=1
    )

    col1, col2 = st.sidebar.columns([1, 1])
    if col1.button("Tally", use_container_width=True):
        tally_votes(n, t, p)

    if col2.button("Reset", use_container_width=True, type="primary"):
        for filename in os.listdir(votes_dir):
            file_path = os.path.join(votes_dir, filename)
            os.remove(file_path)
        st.warning("Votes reset.")

    st.header("Choose the next leader of the Avengers :superhero:")
    st.image("./images/candidates.jpg", use_column_width=True)

    candidates_captions = [
        "Steve Rogers, the super-soldier and the first Avenger.",
        "Tony Stark, the genius, billionaire, playboy, philanthropist.",
        "Thor, the God of Thunder and the rightful king of Asgard.",
    ]

    candidate = st.radio(
        options=candidates,
        label="Candidates",
        horizontal=True,
        captions=candidates_captions,
        label_visibility="collapsed",
    )

    if st.button("Vote", use_container_width=True):
        if voter_id:
            cast_vote(voter_id, candidate)
        else:
            st.error("Please enter your voter ID.")


if __name__ == "__main__":
    main()
