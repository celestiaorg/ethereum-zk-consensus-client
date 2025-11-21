use sp1_build::build_program_with_args;

fn main() {
    build_program_with_args("../circuit", Default::default());
    build_program_with_args("../mock", Default::default());
}
