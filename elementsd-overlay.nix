final: prev: {

  elementsd = prev.elementsd.overrideAttrs (oldAttrs: rec {
    version = "23.2.4";

    src = final.fetchFromGitHub {
      owner = "ElementsProject";
      repo = "elements";
      rev = "elements-${version}";
      sha256 = "sha256-UNjYkEZBjGuhkwBxSkNXjBBcLQqoan/afCLhoR2lOY4=";
    };
  });
}
