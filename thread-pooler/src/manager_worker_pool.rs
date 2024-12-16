use std::borrow::{Borrow, BorrowMut};
use std::cell::RefCell;
use std::clone::Clone;
use std::io::{Error, ErrorKind, Result};
use std::ops::ControlFlow;
use std::sync::{Arc, RwLock};
use std::thread::{current, Builder, JoinHandle};
use std::marker::{Send, Sync};
use std::sync::mpsc::{channel, Receiver, Sender};

use rand::random;
use uuid::Uuid;

#[derive(Clone)]
pub enum WorkerState<U> where U: Clone + Send + Sync {
  Idle,
  Busy,
  Finished(U),
  Dead(Arc<Error>), // TODO wack
}

pub struct Worker<T, U> where T: Clone + Send + Sync, U: Clone + Send + Sync {
  sender: Sender<T>,
  handle: Option<JoinHandle<()>>,
  state: WorkerState<U>,
}

impl<T: Clone + Send + Sync + 'static, U: Clone + Send + Sync + 'static> Worker<T, U> { 
  pub fn new<WorkerFn: Fn(Receiver<T>, Arc<RwLock<Worker<T, U>>>) -> ControlFlow<Result<U>, ()> + Sync + Send + 'static>(worker_fn: WorkerFn) -> Result<Arc<RwLock<Self>>> {
    let (sender, receiver) = channel();

    let worker = Arc::new(RwLock::new(Self {
      sender,
      handle: None,
      state: WorkerState::Idle,
    }));

    let handle = Builder::new().name(Uuid::new_v4().to_string())
      .spawn(move || {
        let move_receiver = receiver;
        loop {
          match do_with_write_lock(worker.clone(), |w| Ok(w.set_state(WorkerState::Idle))) {
            Ok(_) => {}
            Err(_) => continue,
          }
          match worker_fn(move_receiver, worker.clone()) {
            ControlFlow::Break(result) => match &result {
              Ok(value) => {
                let _ = do_with_write_lock(worker.clone(), |w| Ok(w.set_state(WorkerState::Finished(value.clone()))));
                break;
              }
              Err(error) => {
                let _ = do_with_write_lock(worker.clone(), |w| Ok(w.set_state(WorkerState::Dead(Arc::new(error.clone())))));
                break;
              }
            }
            ControlFlow::Continue(_) => {}
          }
        }
      })?;

    do_with_write_lock(worker.clone(), move |w| Ok(w.set_handle(handle)))?;
    
    Ok(worker.clone())
  }

  pub fn send(&mut self, data: T) -> Result<()> {
    match self.sender.send(data) {
      Ok(_) => {}
      Err(error) => return Err(Error::new(ErrorKind::Other, error)) 
    }
    self.set_state(WorkerState::Busy);
    Ok(())
  }

  pub fn set_state(&mut self, state: WorkerState<U>) {
    self.state = state;
  }

  pub fn set_handle(&mut self, handle: JoinHandle<()>) {
    self.handle = Some(handle)
  }

  pub fn kill(&mut self) {
    todo!()
  }

  pub fn get_state(&mut self) -> WorkerState<U> {
    // this stinks lmao
    match &self.handle {
      Some(handle) if handle.is_finished() => self.wait_join(),
      _ => self.state.clone()
    }
  }

  pub fn wait_join(&mut self) -> WorkerState<U> {
    match self.handle {
      Some(_) => {
        let handle = self.handle.take().unwrap();
        self.handle = None;
        match handle.join() {
          Ok(_) => {}
          Err(_) => {
            self.state = WorkerState::Dead(Arc::new(Error::new(ErrorKind::Other, "Join errored"))); // TODO dont just drop this
          }
        }
      }
      _ => {}
    };
    self.state.clone()
  }
}

// TODO I don't like this function. I want a type that I can wrap the functions in but I don't have it. Maybe macro????
pub fn do_with_write_lock<R, T: Clone + Send + Sync + 'static, 
                          U: Clone + Send + Sync + 'static,
                          F: FnMut(&mut Worker<T, U>) -> Result<R>>(mut worker: Arc<RwLock<Worker<T, U>>>, mut func: F) -> Result<R> 
{
  match worker.borrow_mut().write() {
    Ok(mut locked_worker) => func(&mut locked_worker),
    Err(_) => {
      worker.borrow_mut().clear_poison();
      Err(Error::new(ErrorKind::Other, "RwLock was poisoned. The poisoning was cleared"))
    }
  }
}

pub struct ManagerWorkerPool<T: Clone + Send + Sync, U: Clone + Send + Sync, WorkerBuilder: Fn() -> Result<Arc<RwLock<Worker<T, U>>>>> {
  // configuration
  worker_count: usize,
  kill_timeout_ms: usize,
  worker_builder: Option<WorkerBuilder>,

  // management
  worker_threads: Vec<Arc<RwLock<Worker<T, U>>>>,
}

impl<T: Clone + Send + Sync + 'static, U: Clone + Send + Sync + 'static, WorkerBuilder: Fn() -> Result<Arc<RwLock<Worker<T, U>>>>> ManagerWorkerPool<T, U, WorkerBuilder> { 
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
    self.worker_threads.push(unwrapped_builder()?);
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

  fn select_random_worker(&self) -> Result<Arc<RwLock<Worker<T, U>>>> {
    for worker in &self.worker_threads {
      match do_with_write_lock(worker.clone(), |w| Ok(w.get_state())) {
        Ok(WorkerState::Idle) => return Ok(worker.clone()),
        _ => {}
      }
    }
    Err(Error::new(ErrorKind::ConnectionRefused, "All workers in thread pool are busy :("))
  }

  // TODO this should be in a separate thread so we can run multiple thread pools at the same time
  pub fn start_manager<F: Fn() -> ControlFlow<(), T>>(&mut self, manager_fn: F) -> Result<()> {
    loop {
      self.build_missing_workers()?;
      match manager_fn() {
        ControlFlow::Break(_) => break,
        ControlFlow::Continue(data) => {
          match self.select_random_worker() {
            Ok(worker) => match do_with_write_lock(worker, |w| w.send(data.clone())) {
              Ok(_) => continue,
              Err(_) => continue, // TODO need to not just ignore these errors maybe have configurable handlers for these???
            },
            Err(_) => continue, // TODO need to not just ignore these errors maybe have configurable handlers for these???
          }
        }
      }
    }
    for worker in &self.worker_threads {
      let _ = do_with_write_lock(worker.clone(), |w| Ok(w.wait_join()));
    }
    Ok(())
  }
}