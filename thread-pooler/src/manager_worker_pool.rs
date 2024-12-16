use std::any::Any;
use std::clone::Clone;
use std::io::{Error, ErrorKind, Result};
use std::ops::ControlFlow;
use std::sync::Arc;
//use std::os::unix::thread::JoinHandleExt;
use std::thread::{Builder, JoinHandle};
use std::marker::{Send, Sync};
//{Arc, Condvar, Mutex};
use std::sync::mpsc::{channel, Receiver, Sender};

use rand::random;
use uuid::Uuid;

pub enum WorkerState<U> {
  Idle,
  Busy,
  Finished(U),
  Dead(Box<dyn Any + Send>),
}

struct Worker<T, U> where T: Send + Sync, U: Send {
  sender: Sender<T>,
  handle: JoinHandle<Result<U>>,
  state: WorkerState<U>,
}

impl<T: Send + Sync + 'static, U: Send + 'static> Worker<T, U> { 
  pub fn new<WorkerFn: Fn(Receiver<T>) -> Result<U> + Send + 'static>(worker_fn: WorkerFn) -> Result<Self> {
    let (sender, receiver) = channel();
    let handle = Builder::new().name(Uuid::new_v4().to_string())
      .spawn(move || worker_fn(receiver))?;
    
    Ok(Self {
      sender,
      handle,
      state: WorkerState::Idle
    })
  }

  pub fn send(&mut self, data: T) -> Result<()> {
    match self.sender.send(data) {
      Ok(_) => {}
      Err(error) => return Err(Error::new(ErrorKind::Other, error))
    }
    self.state = WorkerState::Busy;
    Ok(())
  }

  pub fn kill(&mut self) {
    todo!()
  }

  pub fn get_state(&self) -> WorkerState<U> {
    // this stinks lmao
    if self.handle.is_finished() {
      self.wait()
    } else {
      // todo wack
      match self.state {
        WorkerState::Idle => WorkerState::Idle,
        WorkerState::Busy => WorkerState::Busy,
        _ => todo!()
      }
    }
  }

  pub fn wait(&self) -> WorkerState<U> {
    match self.handle.join() {
      Ok(result) => match result {
        Ok(value) => WorkerState::Finished(value),
        Err(error) => WorkerState::Dead(Box::new(error))
      }
      Err(error) => WorkerState::Dead(error)
    }
  }
}

pub struct ManagerWorkerPool<T: Send + Sync, U: Send, WorkerBuilder: Fn() -> Worker<T, U>> {
  // configuration
  worker_count: usize,
  kill_timeout_ms: usize,
  worker_builder: Option<WorkerBuilder>,

  // management
  worker_threads: Vec<Arc<Worker<T, U>>>,
}

impl<T: Send + Sync + 'static, U: Clone + Send + 'static, WorkerBuilder: Fn() -> Worker<T, U>> ManagerWorkerPool<T, U, WorkerBuilder> { 
  pub fn new(worker_count: usize) -> Self {
    Self {
      worker_count,
      kill_timeout_ms: 20_000, // TODO idk what this should be
      worker_builder: None,
      worker_threads: Vec::new(),
    }
  }

  pub fn set_kill_timeout_ms(&mut self, kill_timeout_ms: usize) {
    self.kill_timeout_ms = kill_timeout_ms;
  }

  pub fn set_worker_builder(&mut self, worker_builder: WorkerBuilder) {
    self.worker_builder = Some(worker_builder);
  }

  // TODO unsure about the worker function return type
  fn spawn_worker(&mut self) -> Result<()> {
    if self.worker_builder.is_none() {
      return Err(Error::new(ErrorKind::NotFound, "Missing worker builder :("))
    }

    let unwrapped_builder = self.worker_builder.as_ref().unwrap();
    self.worker_threads.push(Arc::new(unwrapped_builder()));
    Ok(())
  }

  fn build_missing_workers(&mut self) -> Result<()> {
    if self.worker_threads.len() >= self.worker_count {
      return Ok(());
    }

    let missing_count = self.worker_count - self.worker_threads.len();
    for _ in 0..missing_count {
      self.spawn_worker()?;
    }

    Ok(())
  }

  fn select_random_worker(&self) -> &Worker<T, U> {
    let idx = random::<usize>() % self.worker_count as usize;
    self.worker_threads.get(idx).unwrap()
  }

  pub fn start_manager<F: Fn(&Worker<T, U>) -> ControlFlow<(), ()>>(&mut self, manager_fn: F) -> Result<()> {
    loop {
      self.build_missing_workers();
      let worker = self.select_random_worker();
      match manager_fn(worker) {
        ControlFlow::Break(_) => break,
        ControlFlow::Continue(_) => continue
      }
    }
    for worker in &self.worker_threads {
      worker.wait();
    }
    Ok(())
  }
}