import subprocess

from argo.test_database import MONGODB_IMAGE

if __name__ == "__main__":
    subprocess.run(["docker", "pull", MONGODB_IMAGE], check=True)
    print("Installed pinned MongoDB test database")
