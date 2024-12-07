import typer


app = typer.Typer()


@app.command()
def main() -> int:
    print("Hello from uv-secure!")
    return 0


if __name__ == "__main__":
    app()
