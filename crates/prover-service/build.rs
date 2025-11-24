use sp1_build::build_program_with_args;

fn main() {
    build_program_with_args("../sp1-helios", Default::default());
    build_program_with_args("../mock", Default::default());
}
