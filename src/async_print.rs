use std::{os::fd::AsFd, rc::Rc};

use monoio::fs::File;

#[macro_export]
macro_rules! aeprintln {
  ($($arg:tt)*) => {
    $crate::async_print::print_stderr(format!("{}\n", format_args!($($arg)*))).await
  };
}

pub async fn print_stderr(msg: String) {
    thread_local! {
      static STDERR: Rc<File> = Rc::new(File::from_std(
        std::fs::File::from(
          std::io::stderr().as_fd().try_clone_to_owned()
            .expect("failed to clone stderr")
        )).unwrap());
    }
    let stderr = STDERR.with(|x| x.clone());
    let _ = stderr.write_all_at(msg.into_bytes(), 0).await;
}
